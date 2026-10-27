package ipscope

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Option configures a Client instance.
type Option func(*clientConfig)

type clientConfig struct {
	baseURL    string
	timeout    time.Duration
	retry      RetryOptions
	cache      CacheOptions
	userAgent  string
	httpClient *http.Client
}

// WithBaseURL overrides the default IPScope API base URL (`https://api.ipscope.io`).
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) {
		trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if trimmed != "" {
			c.baseURL = trimmed
		}
	}
}

// WithTimeout sets the per-request HTTP timeout (default: `5s`).
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

// WithRetryOptions configures retry behavior for 429 and transient 502/503/504 responses.
func WithRetryOptions(retry RetryOptions) Option {
	return func(c *clientConfig) {
		c.retry = retry
	}
}

// WithCacheOptions configures the bounded in-memory O(1) LRU + TTL cache.
func WithCacheOptions(cache CacheOptions) Option {
	return func(c *clientConfig) {
		c.cache = cache
	}
}

// WithHTTPClient provides a custom `*http.Client` (e.g., for custom TLS, proxy, or test transports).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = httpClient
	}
}

// WithUserAgent appends a custom application identifier to the SDK `User-Agent` header.
func WithUserAgent(userAgent string) Option {
	return func(c *clientConfig) {
		c.userAgent = strings.TrimSpace(userAgent)
	}
}

// Client is the official concurrency-safe Go server-side client for the IPScope IP Intelligence API.
//
// It exposes strictly IP intelligence, CIDR network prefix, dataset metadata, feedback, and status
// operations - with zero account, wallet, or billing operations.
type Client struct {
	transport    *httpTransport
	ipCache      *lruTTLCache[*IPLookupResponse]
	networkCache *lruTTLCache[*NetworkPrefixLookupResponse]
}

// NewClient creates a new IPScope Go SDK client for the given server-side API key.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	validKey, err := ValidateAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	cfg := &clientConfig{
		baseURL: DefaultBaseURL,
		timeout: DefaultTimeout,
		retry: RetryOptions{
			MaxRetries:       2,
			BaseDelay:        150 * time.Millisecond,
			MaxDelay:         3 * time.Second,
			RetryOnRateLimit: true,
		},
		cache: CacheOptions{
			Enabled:    true,
			MaxEntries: DefaultCacheMaxEntries,
			TTL:        DefaultCacheTTL,
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	if cfg.retry.BaseDelay <= 0 {
		cfg.retry.BaseDelay = 150 * time.Millisecond
	}
	if cfg.retry.MaxDelay <= 0 {
		cfg.retry.MaxDelay = 3 * time.Second
	}

	userAgent := SDKUserAgent
	if cfg.userAgent != "" {
		userAgent = cfg.userAgent + " " + SDKUserAgent
	}

	ownsClient := cfg.httpClient == nil
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = newDefaultHTTPClient(cfg.timeout)
	}

	netMaxEntries := min(128, max(1, cfg.cache.MaxEntries))

	return &Client{
		transport: &httpTransport{
			apiKey:     validKey,
			baseURL:    cfg.baseURL,
			timeout:    cfg.timeout,
			retry:      cfg.retry,
			userAgent:  userAgent,
			httpClient: httpClient,
			ownsClient: ownsClient,
		},
		ipCache: newLRUTTLCache[*IPLookupResponse](cfg.cache),
		networkCache: newLRUTTLCache[*NetworkPrefixLookupResponse](CacheOptions{
			Enabled:    cfg.cache.Enabled,
			MaxEntries: netMaxEntries,
			TTL:        cfg.cache.TTL,
		}),
	}, nil
}

// Close releases idle HTTP connections and clears in-memory LRU caches.
func (c *Client) Close() {
	c.ClearCache()
	c.transport.close()
}

// LookupIP looks up IP intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/:ip`).
// Concurrent lookups for the same IP are automatically singleflight-coalesced.
func (c *Client) LookupIP(ctx context.Context, rawIP string, reqOpts ...RequestOptions) (*IPLookupResponse, error) {
	res, err := c.LookupIPWithMeta(ctx, rawIP, reqOpts...)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// LookupIPWithMeta looks up a single IPv4 or IPv6 address and returns both the response and rate-limit metadata.
func (c *Client) LookupIPWithMeta(
	ctx context.Context,
	rawIP string,
	reqOpts ...RequestOptions,
) (*ResultWithMeta[*IPLookupResponse], error) {
	canonicalIP, _, err := ValidateIPAddress(rawIP)
	if err != nil {
		return nil, err
	}

	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	lastStatus := http.StatusOK
	var lastRL RateLimitMetadata
	if prev := c.transport.getLastRateLimit(); prev != nil {
		lastRL = *prev
	}

	val, fromCache, err := c.ipCache.GetOrCompute(
		ctx,
		canonicalIP,
		opt.BypassCache,
		func(callCtx context.Context) (*IPLookupResponse, error) {
			path := "/v1/ip/" + url.PathEscape(canonicalIP)
			bodyBytes, status, rl, reqErr := c.transport.doRequest(callCtx, http.MethodGet, path, nil, opt.Headers, true)
			if reqErr != nil {
				return nil, reqErr
			}
			lastStatus = status
			lastRL = rl

			var parsed IPLookupResponse
			if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
				return nil, &APIError{
					Message: fmt.Sprintf("failed to decode IP lookup response: %v", unmarshalErr),
					Code:    ErrCodeNetwork,
					Status:  status,
					Path:    path,
					Cause:   unmarshalErr,
				}
			}

			respIP := strings.ToLower(strings.TrimSpace(parsed.IP))
			if respIP != "" && respIP != canonicalIP {
				c.ipCache.Set(respIP, &parsed)
			}
			return &parsed, nil
		},
	)
	if err != nil {
		return nil, err
	}

	if fromCache {
		if prev := c.transport.getLastRateLimit(); prev != nil {
			lastRL = *prev
		}
	}

	return &ResultWithMeta[*IPLookupResponse]{
		Data:      val,
		Status:    lastStatus,
		RateLimit: lastRL,
		FromCache: fromCache,
	}, nil
}

// LookupCallerIP looks up intelligence for the caller's own server-observed IP (`GET /v1/ip/me`).
func (c *Client) LookupCallerIP(ctx context.Context, reqOpts ...RequestOptions) (*IPLookupResponse, error) {
	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}
	bodyBytes, status, _, err := c.transport.doRequest(ctx, http.MethodGet, "/v1/ip/me", nil, opt.Headers, true)
	if err != nil {
		return nil, err
	}

	var parsed IPLookupResponse
	if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
		return nil, &APIError{
			Message: fmt.Sprintf("failed to decode caller IP response: %v", unmarshalErr),
			Code:    ErrCodeNetwork,
			Status:  status,
			Path:    "/v1/ip/me",
			Cause:   unmarshalErr,
		}
	}
	return &parsed, nil
}

// LookupBatch performs a batch lookup for 1..100 IPs (`POST /v1/ip/batch`), deduplicating
// wire requests and reusing warm LRU cache entries automatically.
func (c *Client) LookupBatch(ctx context.Context, rawIPs []string, reqOpts ...RequestOptions) (*BatchLookupResponse, error) {
	orderedIPs, uniqueIPs, err := ValidateAndDeduplicateBatchIPs(rawIPs, MaxSingleBatchSize)
	if err != nil {
		return nil, err
	}

	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	resolvedByIP := make(map[string]*IPLookupResponse, len(uniqueIPs))
	missingIPs := make([]string, 0, len(uniqueIPs))

	if !opt.BypassCache {
		for _, ipStr := range uniqueIPs {
			if cached, ok := c.ipCache.Get(ipStr); ok {
				resolvedByIP[ipStr] = cached
			} else {
				missingIPs = append(missingIPs, ipStr)
			}
		}
	} else {
		missingIPs = append(missingIPs, uniqueIPs...)
	}

	var datasetVersion string

	if len(missingIPs) > 0 {
		payload := map[string]any{"ips": missingIPs}
		bodyBytes, status, _, reqErr := c.transport.doRequest(ctx, http.MethodPost, "/v1/ip/batch", payload, opt.Headers, true)
		if reqErr != nil {
			return nil, reqErr
		}

		var batchParsed BatchLookupResponse
		if unmarshalErr := json.Unmarshal(bodyBytes, &batchParsed); unmarshalErr != nil {
			return nil, &APIError{
				Message: fmt.Sprintf("failed to decode batch lookup response: %v", unmarshalErr),
				Code:    ErrCodeNetwork,
				Status:  status,
				Path:    "/v1/ip/batch",
				Cause:   unmarshalErr,
			}
		}
		datasetVersion = batchParsed.DatasetVersion

		for idx, reqIP := range missingIPs {
			if idx < len(batchParsed.Results) && batchParsed.Results[idx] != nil {
				item := batchParsed.Results[idx]
				resolvedByIP[reqIP] = item
				c.ipCache.Set(reqIP, item)
				respIP := strings.ToLower(strings.TrimSpace(item.IP))
				if respIP != "" && respIP != reqIP {
					c.ipCache.Set(respIP, item)
				}
			}
		}
	}

	orderedResults := make([]*IPLookupResponse, len(orderedIPs))
	for i, ipStr := range orderedIPs {
		orderedResults[i] = resolvedByIP[ipStr]
	}
	if datasetVersion == "" && len(orderedResults) > 0 && orderedResults[0] != nil {
		datasetVersion = orderedResults[0].DatasetVersion
	}

	return &BatchLookupResponse{
		DatasetVersion: datasetVersion,
		Count:          len(orderedResults),
		Results:        orderedResults,
	}, nil
}

// LookupBatchChunked performs a batch lookup for >100 IPs by deduplicating and executing
// chunks of up to 100 IPs with bounded goroutine concurrency (default: 4 workers).
func (c *Client) LookupBatchChunked(
	ctx context.Context,
	rawIPs []string,
	concurrency int,
	reqOpts ...RequestOptions,
) (*BatchLookupResponse, error) {
	orderedIPs, uniqueIPs, err := ValidateAndDeduplicateBatchIPs(rawIPs, 0)
	if err != nil {
		return nil, err
	}

	workers := concurrency
	if workers <= 0 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}

	var chunks [][]string
	for i := 0; i < len(uniqueIPs); i += MaxSingleBatchSize {
		end := min(i+MaxSingleBatchSize, len(uniqueIPs))
		chunks = append(chunks, uniqueIPs[i:end])
	}

	var (
		mu             sync.Mutex
		resolvedByIP   = make(map[string]*IPLookupResponse, len(uniqueIPs))
		datasetVersion string
		firstErr       error
	)

	ctxChunk, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, chunk := range chunks {
		wg.Add(1)
		go func(ch []string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctxChunk.Done():
				return
			}

			res, chunkErr := c.LookupBatch(ctxChunk, ch, reqOpts...)
			mu.Lock()
			defer mu.Unlock()
			if chunkErr != nil {
				if firstErr == nil {
					firstErr = chunkErr
					cancel()
				}
				return
			}
			if datasetVersion == "" && res.DatasetVersion != "" {
				datasetVersion = res.DatasetVersion
			}
			for idx, reqIP := range ch {
				if idx < len(res.Results) {
					resolvedByIP[reqIP] = res.Results[idx]
				}
			}
		}(chunk)
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	orderedResults := make([]*IPLookupResponse, len(orderedIPs))
	for i, ipStr := range orderedIPs {
		orderedResults[i] = resolvedByIP[ipStr]
	}

	return &BatchLookupResponse{
		DatasetVersion: datasetVersion,
		Count:          len(orderedResults),
		Results:        orderedResults,
	}, nil
}

// LookupBatchStream returns a constant-RAM Go 1.23+ iterator (`iter.Seq2[*BatchLookupResponse, error]`)
// that yields batch chunks of up to 100 IPs without accumulating all results in memory.
func (c *Client) LookupBatchStream(
	ctx context.Context,
	rawIPs []string,
	reqOpts ...RequestOptions,
) iter.Seq2[*BatchLookupResponse, error] {
	return func(yield func(*BatchLookupResponse, error) bool) {
		if len(rawIPs) == 0 {
			yield(nil, &ValidationError{
				Field:   "ips",
				Message: "batch IPs slice must contain at least 1 IP address",
			})
			return
		}

		for i := 0; i < len(rawIPs); i += MaxSingleBatchSize {
			end := min(i+MaxSingleBatchSize, len(rawIPs))
			chunk := rawIPs[i:end]
			res, err := c.LookupBatch(ctx, chunk, reqOpts...)
			if !yield(res, err) || err != nil {
				return
			}
		}
	}
}

// LookupNetwork inspects canonical network prefix intelligence by CIDR notation (`GET /v1/networks/:prefix/:length`).
func (c *Client) LookupNetwork(ctx context.Context, rawCIDR string, reqOpts ...RequestOptions) (*NetworkPrefixLookupResponse, error) {
	addrStr, prefixLen, _, canonicalCIDR, err := ValidateCIDRPrefix(rawCIDR)
	if err != nil {
		return nil, err
	}

	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	val, _, err := c.networkCache.GetOrCompute(
		ctx,
		canonicalCIDR,
		opt.BypassCache,
		func(callCtx context.Context) (*NetworkPrefixLookupResponse, error) {
			path := "/v1/networks/" + url.PathEscape(addrStr) + "/" + strconv.Itoa(prefixLen)
			bodyBytes, status, _, reqErr := c.transport.doRequest(callCtx, http.MethodGet, path, nil, opt.Headers, true)
			if reqErr != nil {
				return nil, reqErr
			}

			var parsed NetworkPrefixLookupResponse
			if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
				return nil, &APIError{
					Message: fmt.Sprintf("failed to decode network prefix response: %v", unmarshalErr),
					Code:    ErrCodeNetwork,
					Status:  status,
					Path:    path,
					Cause:   unmarshalErr,
				}
			}
			return &parsed, nil
		},
	)
	return val, err
}

// GetDatasetsMetadata lists active and historical dataset snapshot versions (`GET /v1/metadata/datasets`).
func (c *Client) GetDatasetsMetadata(ctx context.Context, reqOpts ...RequestOptions) (*DatasetsMetadataResponse, error) {
	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	bodyBytes, status, _, err := c.transport.doRequest(ctx, http.MethodGet, "/v1/metadata/datasets", nil, opt.Headers, true)
	if err != nil {
		return nil, err
	}

	var parsed DatasetsMetadataResponse
	if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
		return nil, &APIError{
			Message: fmt.Sprintf("failed to decode datasets metadata response: %v", unmarshalErr),
			Code:    ErrCodeNetwork,
			Status:  status,
			Path:    "/v1/metadata/datasets",
			Cause:   unmarshalErr,
		}
	}
	return &parsed, nil
}

// SubmitFeedback submits geolocation, ASN, or anonymity correction feedback (`POST /v1/feedback`).
func (c *Client) SubmitFeedback(
	ctx context.Context,
	feedback FeedbackSubmissionInput,
	reqOpts ...RequestOptions,
) (*FeedbackSubmissionResponse, error) {
	target := strings.TrimSpace(feedback.PrefixOrIP)
	if strings.Contains(target, "/") {
		if _, _, _, _, err := ValidateCIDRPrefix(target); err != nil {
			return nil, err
		}
	} else {
		if _, _, err := ValidateIPAddress(target); err != nil {
			return nil, err
		}
	}
	feedback.PrefixOrIP = target

	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	bodyBytes, status, _, err := c.transport.doRequest(ctx, http.MethodPost, "/v1/feedback", feedback, opt.Headers, true)
	if err != nil {
		return nil, err
	}

	var parsed FeedbackSubmissionResponse
	if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
		return nil, &APIError{
			Message: fmt.Sprintf("failed to decode feedback submission response: %v", unmarshalErr),
			Code:    ErrCodeNetwork,
			Status:  status,
			Path:    "/v1/feedback",
			Cause:   unmarshalErr,
		}
	}
	return &parsed, nil
}

// GetStatus fetches public service health and active snapshot status (`GET /v1/status`).
func (c *Client) GetStatus(ctx context.Context, reqOpts ...RequestOptions) (*ServiceStatusResponse, error) {
	var opt RequestOptions
	if len(reqOpts) > 0 {
		opt = reqOpts[0]
	}

	bodyBytes, status, _, err := c.transport.doRequest(ctx, http.MethodGet, "/v1/status", nil, opt.Headers, false)
	if err != nil {
		return nil, err
	}

	var parsed ServiceStatusResponse
	if unmarshalErr := json.Unmarshal(bodyBytes, &parsed); unmarshalErr != nil {
		return nil, &APIError{
			Message: fmt.Sprintf("failed to decode service status response: %v", unmarshalErr),
			Code:    ErrCodeNetwork,
			Status:  status,
			Path:    "/v1/status",
			Cause:   unmarshalErr,
		}
	}
	if parsed.Snapshot != nil {
		parsed.CurrentVersion = parsed.Snapshot.CurrentVersion
		parsed.PreviousVersion = parsed.Snapshot.PreviousVersion
	}
	return &parsed, nil
}

// GetLastRateLimit returns the most recently observed user-scoped rate-limit headers.
func (c *Client) GetLastRateLimit() *RateLimitMetadata {
	return c.transport.getLastRateLimit()
}

// GetCacheStats returns hit/miss/singleflight telemetry for the in-memory IP LRU cache.
func (c *Client) GetCacheStats() CacheStats {
	return c.ipCache.Stats()
}

// ClearCache clears both the IP and network prefix in-memory LRU caches.
func (c *Client) ClearCache() {
	c.ipCache.Clear()
	c.networkCache.Clear()
}
