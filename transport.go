package ipscope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the default production base URL for the IPScope API.
	DefaultBaseURL = "https://api.ipscope.io"
	// DefaultTimeout is the default per-request timeout.
	DefaultTimeout = 5 * time.Second
	// MaxResponseBytes is the hard 2 MiB response body ceiling to protect Go heap memory.
	MaxResponseBytes = 2 * 1024 * 1024
	// SDKUserAgent is the default User-Agent header sent by the Go SDK.
	SDKUserAgent = "ipscope-go/1.0.0"
)

type httpTransport struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	retry      RetryOptions
	userAgent  string
	httpClient *http.Client
	ownsClient bool

	mu            sync.RWMutex
	lastRateLimit *RateLimitMetadata
}

func newDefaultHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func parseRateLimitHeaders(h http.Header) RateLimitMetadata {
	parseInt := func(key string) *int {
		raw := strings.TrimSpace(h.Get(key))
		if raw == "" {
			return nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil
		}
		return &v
	}
	parseInt64 := func(key string) *int64 {
		raw := strings.TrimSpace(h.Get(key))
		if raw == "" {
			return nil
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil
		}
		return &v
	}

	return RateLimitMetadata{
		LimitPerMinute:    parseInt("x-ratelimit-limit"),
		Remaining:         parseInt("x-ratelimit-remaining"),
		ResetEpochSeconds: parseInt64("x-ratelimit-reset"),
		Scope:             strings.TrimSpace(h.Get("x-ratelimit-scope")),
		BurstCapacity:     parseInt("x-ratelimit-burst"),
		RateLimitRPS:      parseInt("x-ratelimit-rps"),
	}
}

func extractErrorMessage(bodyBytes []byte, status int, path string) string {
	if len(bodyBytes) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			if msg, ok := payload["message"].(string); ok && strings.TrimSpace(msg) != "" {
				return strings.TrimSpace(msg)
			}
			if arr, ok := payload["message"].([]any); ok && len(arr) > 0 {
				parts := make([]string, 0, len(arr))
				for _, item := range arr {
					parts = append(parts, fmt.Sprint(item))
				}
				return strings.Join(parts, "; ")
			}
		}
	}
	return fmt.Sprintf("IPScope API error (%d) on %s", status, path)
}

func computeRetryAfter(h http.Header, rl RateLimitMetadata) time.Duration {
	if raw := strings.TrimSpace(h.Get("Retry-After")); raw != "" {
		if secs, err := strconv.ParseFloat(raw, 64); err == nil && secs >= 0 {
			return time.Duration(secs * float64(time.Second))
		}
	}
	if rl.ResetEpochSeconds != nil {
		delta := time.Until(time.Unix(*rl.ResetEpochSeconds, 0))
		if delta > 0 {
			return delta
		}
	}
	return 0
}

func computeBackoff(attempt int, retry RetryOptions) time.Duration {
	shift := min(attempt, 10)
	exp := retry.BaseDelay * time.Duration(1<<shift)
	if exp > retry.MaxDelay {
		exp = retry.MaxDelay
	}
	jitterMax := max(int64(exp)/4, int64(5*time.Millisecond))
	jitter := time.Duration(rand.Int64N(jitterMax))
	total := exp + jitter
	if total > retry.MaxDelay {
		return retry.MaxDelay
	}
	return total
}

func sleepWithContext(ctx context.Context, d time.Duration, path string) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return &TimeoutError{Path: path, Cause: ctx.Err()}
		default:
			return nil
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return &TimeoutError{Path: path, Cause: ctx.Err()}
	}
}

func (t *httpTransport) getLastRateLimit() *RateLimitMetadata {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.lastRateLimit == nil {
		return nil
	}
	cp := *t.lastRateLimit
	return &cp
}

func (t *httpTransport) close() {
	if t.ownsClient && t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
}

func (t *httpTransport) doRequest(
	ctx context.Context,
	method string,
	path string,
	reqBody any,
	extraHeaders map[string]string,
	requiresAuth bool,
) ([]byte, int, RateLimitMetadata, error) {
	url := t.baseURL + path

	var bodyBytes []byte
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return nil, 0, RateLimitMetadata{}, &ValidationError{
				Field:   "body",
				Message: fmt.Sprintf("failed to marshal request JSON: %v", err),
			}
		}
		bodyBytes = encoded
	}

	maxRetries := max(0, t.retry.MaxRetries)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, t.timeout)
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)
		if err != nil {
			cancel()
			return nil, 0, RateLimitMetadata{}, &APIError{
				Message: err.Error(),
				Code:    ErrCodeNetwork,
				Path:    path,
				Cause:   err,
			}
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", t.userAgent)
		if requiresAuth {
			req.Header.Set("x-api-key", t.apiKey)
			req.Header.Set("Authorization", "Bearer "+t.apiKey)
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, doErr := t.httpClient.Do(req)
		if doErr != nil {
			cancel()
			if errors.Is(doErr, context.DeadlineExceeded) || errors.Is(doErr, context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, 0, RateLimitMetadata{}, &TimeoutError{
					Path:    path,
					Timeout: t.timeout,
					Cause:   doErr,
				}
			}
			if attempt < maxRetries {
				if sleepErr := sleepWithContext(ctx, computeBackoff(attempt, t.retry), path); sleepErr != nil {
					return nil, 0, RateLimitMetadata{}, sleepErr
				}
				continue
			}
			return nil, 0, RateLimitMetadata{}, &APIError{
				Message: fmt.Sprintf("network request to %q failed: %v", path, doErr),
				Code:    ErrCodeNetwork,
				Path:    path,
				Cause:   doErr,
			}
		}

		// Always read with 2 MiB hard ceiling and close body to return connection to pool
		respBytes, status, respHeader, readErr := readBoundedResponse(resp, path)
		cancel()
		if readErr != nil {
			return nil, status, RateLimitMetadata{}, readErr
		}

		rl := parseRateLimitHeaders(respHeader)
		t.mu.Lock()
		t.lastRateLimit = &rl
		t.mu.Unlock()

		if status >= 200 && status < 300 {
			return respBytes, status, rl, nil
		}

		errMsg := extractErrorMessage(respBytes, status, path)

		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			code := ErrCodeUnauthorized
			if status == http.StatusForbidden {
				code = ErrCodeForbiddenScope
			}
			return nil, status, rl, &APIError{
				Message:   errMsg,
				Code:      code,
				Status:    status,
				Path:      path,
				RateLimit: &rl,
			}
		}

		if status == http.StatusTooManyRequests {
			retryAfter := computeRetryAfter(respHeader, rl)
			if t.retry.RetryOnRateLimit && attempt < maxRetries {
				delay := retryAfter
				if delay <= 0 {
					delay = computeBackoff(attempt, t.retry)
				}
				if delay > t.retry.MaxDelay {
					delay = t.retry.MaxDelay
				}
				if sleepErr := sleepWithContext(ctx, delay, path); sleepErr != nil {
					return nil, status, rl, sleepErr
				}
				continue
			}
			return nil, status, rl, &APIError{
				Message:    errMsg,
				Code:       ErrCodeRateLimited,
				Status:     status,
				Path:       path,
				RateLimit:  &rl,
				RetryAfter: retryAfter,
			}
		}

		if (status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout) && attempt < maxRetries {
			if sleepErr := sleepWithContext(ctx, computeBackoff(attempt, t.retry), path); sleepErr != nil {
				return nil, status, rl, sleepErr
			}
			continue
		}

		return nil, status, rl, &APIError{
			Message:   errMsg,
			Code:      ErrorCode(fmt.Sprintf("IPSCOPE_HTTP_%d", status)),
			Status:    status,
			Path:      path,
			RateLimit: &rl,
		}
	}

	return nil, 0, RateLimitMetadata{}, &APIError{
		Message: fmt.Sprintf("exhausted %d retries for %q", maxRetries, path),
		Code:    ErrCodeRetryExhausted,
		Path:    path,
	}
}

func readBoundedResponse(resp *http.Response, path string) ([]byte, int, http.Header, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.ContentLength > MaxResponseBytes {
		return nil, resp.StatusCode, resp.Header, &APIError{
			Message: fmt.Sprintf("IPScope response payload (%d bytes) exceeds 2 MiB safety limit", resp.ContentLength),
			Code:    ErrCodeResponseTooLarge,
			Status:  resp.StatusCode,
			Path:    path,
		}
	}

	limited := io.LimitReader(resp.Body, MaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, resp.StatusCode, resp.Header, &TimeoutError{
				Path:  path,
				Cause: err,
			}
		}
		return nil, resp.StatusCode, resp.Header, &APIError{
			Message: fmt.Sprintf("failed reading response body from %q: %v", path, err),
			Code:    ErrCodeNetwork,
			Status:  resp.StatusCode,
			Path:    path,
			Cause:   err,
		}
	}

	if len(data) > MaxResponseBytes {
		return nil, resp.StatusCode, resp.Header, &APIError{
			Message: "IPScope response payload exceeds 2 MiB safety limit",
			Code:    ErrCodeResponseTooLarge,
			Status:  resp.StatusCode,
			Path:    path,
		}
	}

	return data, resp.StatusCode, resp.Header, nil
}
