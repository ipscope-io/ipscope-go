package ipscope

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeMockIPRecord(ip string) map[string]any {
	version := 4
	cidr := "8.8.8.0/24"
	if strings.Contains(ip, ":") {
		version = 6
		cidr = "2001:4860:4860::/48"
	}
	return map[string]any{
		"ip":              ip,
		"ip_version":      version,
		"matched_network": cidr,
		"geo": map[string]any{
			"country_code":          "US",
			"subdivision":           "California",
			"city":                  "Mountain View",
			"timezone":              "America/Los_Angeles",
			"location_type":         "anycast",
			"confidence":            0.96,
			"accuracy_radius_km":    20.0,
			"declared_country_code": "US",
			"physical_country_code": "US",
			"is_virtual_location":   false,
		},
		"network": map[string]any{
			"asn":          15169,
			"organization": "Google LLC",
		},
		"security": map[string]any{
			"is_vpn":          false,
			"is_hosting":      true,
			"is_tor_exit":     false,
			"is_proxy":        false,
			"anonymizer_type": "none",
			"confidence":      0.99,
			"reason_codes":    []string{"ASN_HOSTING"},
		},
		"connection": map[string]any{
			"connection_type": "hosting",
			"is_residential":  false,
			"is_mobile":       false,
			"is_business":     false,
			"is_hosting":      true,
		},
		"security_extensions": map[string]any{
			"abuse_velocity_score":      0.02,
			"is_known_scanner":          false,
			"observation_recency_hours": 1.5,
		},
		"dataset_version": "2026.10.25-001",
		"updated_at":      "2026-10-25T00:00:00Z",
	}
}

func writeRateLimitHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", "998")
	w.Header().Set("X-RateLimit-Reset", "1761350400")
	w.Header().Set("X-RateLimit-Scope", "user")
	w.Header().Set("X-RateLimit-Burst", "100")
	w.Header().Set("X-RateLimit-RPS", "50")
}

func TestValidationAndStrictIPScope(t *testing.T) {
	key, err := ValidateAPIKey("  ips_live_secret_12345  ")
	if err != nil || key != "ips_live_secret_12345" {
		t.Fatalf("expected valid API key, got %q, err=%v", key, err)
	}

	if _, err := ValidateAPIKey("   "); !IsValidationError(err) {
		t.Fatalf("expected ValidationError for empty API key, got %v", err)
	}
	if _, err := ValidateAPIKey("ips_live_bad\nheader"); !IsValidationError(err) {
		t.Fatalf("expected ValidationError for control char in API key, got %v", err)
	}

	ip4, fam4, err := ValidateIPAddress(" 8.8.8.8 ")
	if err != nil || ip4 != "8.8.8.8" || fam4 != IPFamilyV4 {
		t.Fatalf("expected valid IPv4, got %s (%d), err=%v", ip4, fam4, err)
	}

	ip6, fam6, err := ValidateIPAddress("2001:0db8:0000:0000:0000:0000:0000:0001")
	if err != nil || ip6 != "2001:db8::1" || fam6 != IPFamilyV6 {
		t.Fatalf("expected canonical IPv6 2001:db8::1, got %s (%d), err=%v", ip6, fam6, err)
	}

	if _, _, err := ValidateIPAddress("999.999.999.999"); !IsValidationError(err) {
		t.Fatalf("expected ValidationError for invalid IP, got %v", err)
	}

	addr, bits, fam, cidr, err := ValidateCIDRPrefix("8.8.8.99/24")
	if err != nil || addr != "8.8.8.0" || bits != 24 || fam != IPFamilyV4 || cidr != "8.8.8.0/24" {
		t.Fatalf("unexpected CIDR parse result: addr=%s bits=%d fam=%d cidr=%s err=%v", addr, bits, fam, cidr, err)
	}

	// Ensure zero account, wallet, or billing methods exist on Client
	clientType := reflect.TypeOf(&Client{})
	forbidden := []string{
		"GetWallet", "TopUpWallet", "CreateCheckout", "ListAPIKeys",
		"CreateAPIKey", "RevokeAPIKey", "Login", "Register", "GetBilling",
	}
	for _, method := range forbidden {
		if _, exists := clientType.MethodByName(method); exists {
			t.Fatalf("Client must not expose account/billing method %s", method)
		}
	}
}

func TestSingleLookupCacheAndSingleflightCoalescing(t *testing.T) {
	var hitCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		if r.Header.Get("x-api-key") != "ips_live_valid_key_12345" {
			t.Errorf("missing or invalid x-api-key header: %s", r.Header.Get("x-api-key"))
		}
		time.Sleep(25 * time.Millisecond)
		writeRateLimitHeaders(w)
		_ = json.NewEncoder(w).Encode(makeMockIPRecord("8.8.8.8"))
	}))
	defer srv.Close()

	client, err := NewClient(
		"ips_live_valid_key_12345",
		WithBaseURL(srv.URL),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	const goroutines = 25
	var wg sync.WaitGroup
	results := make([]*IPLookupResponse, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = client.LookupIP(ctx, "8.8.8.8")
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if results[i].IP != "8.8.8.8" || results[i] != results[0] {
			t.Fatalf("expected identical coalesced pointer for goroutine %d", i)
		}
	}

	if got := hitCount.Load(); got != 1 {
		t.Fatalf("expected exactly 1 upstream HTTP call due to singleflight coalescing, got %d", got)
	}

	stats := client.GetCacheStats()
	if stats.Size != 1 || stats.CoalescedInFlightHits == 0 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}

	rl := client.GetLastRateLimit()
	if rl == nil || rl.Remaining == nil || *rl.Remaining != 998 {
		t.Fatalf("expected rate limit remaining=998, got %+v", rl)
	}
}

func TestBatchLookupDeduplicationChunkedAndStream(t *testing.T) {
	var (
		mu         sync.Mutex
		sentBodies [][]string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRateLimitHeaders(w)
		if r.URL.Path == "/v1/ip/8.8.8.8" {
			_ = json.NewEncoder(w).Encode(makeMockIPRecord("8.8.8.8"))
			return
		}
		if r.URL.Path == "/v1/ip/batch" {
			var body struct {
				IPs []string `json:"ips"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			sentBodies = append(sentBodies, body.IPs)
			mu.Unlock()

			records := make([]map[string]any, len(body.IPs))
			for i, ip := range body.IPs {
				records[i] = makeMockIPRecord(ip)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dataset_version": "2026.10.25-001",
				"count":           len(records),
				"results":         records,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient("ips_live_valid_key_12345", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Prime cache with 8.8.8.8
	if _, err := client.LookupIP(ctx, "8.8.8.8"); err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}

	batch, err := client.LookupBatch(ctx, []string{"8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9"})
	if err != nil {
		t.Fatalf("LookupBatch failed: %v", err)
	}
	if batch.Count != 5 || len(batch.Results) != 5 {
		t.Fatalf("expected 5 batch results, got %d", batch.Count)
	}
	mu.Lock()
	if len(sentBodies) != 1 || len(sentBodies[0]) != 2 || sentBodies[0][0] != "1.1.1.1" || sentBodies[0][1] != "9.9.9.9" {
		t.Fatalf("expected only uncached unique IPs [1.1.1.1, 9.9.9.9] sent over wire, got %+v", sentBodies)
	}
	mu.Unlock()

	// Test LookupBatchChunked & LookupBatchStream with 250 IPs
	largeIPs := make([]string, 250)
	for i := range 250 {
		largeIPs[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}

	chunkedRes, err := client.LookupBatchChunked(ctx, largeIPs, 3, RequestOptions{BypassCache: true})
	if err != nil {
		t.Fatalf("LookupBatchChunked failed: %v", err)
	}
	if chunkedRes.Count != 250 {
		t.Fatalf("expected 250 chunked results, got %d", chunkedRes.Count)
	}

	streamedCount := 0
	chunksSeen := 0
	for chunk, streamErr := range client.LookupBatchStream(ctx, largeIPs, RequestOptions{BypassCache: true}) {
		if streamErr != nil {
			t.Fatalf("LookupBatchStream error: %v", streamErr)
		}
		chunksSeen++
		streamedCount += chunk.Count
	}
	if chunksSeen != 3 || streamedCount != 250 {
		t.Fatalf("expected 3 streamed chunks totaling 250 IPs, got %d chunks and %d IPs", chunksSeen, streamedCount)
	}
}

func TestNetworkCallerDatasetsFeedbackAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRateLimitHeaders(w)
		switch r.URL.Path {
		case "/v1/networks/8.8.8.0/24":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"queried_cidr":    "8.8.8.0/24",
				"family":          4,
				"dataset_version": "2026.10.25-001",
				"record": map[string]any{
					"prefix":       "8.8.8.0/24",
					"family":       4,
					"asn":          15169,
					"organization": "Google LLC",
					"country_code": "US",
				},
			})
		case "/v1/ip/me":
			_ = json.NewEncoder(w).Encode(makeMockIPRecord("203.0.113.42"))
		case "/v1/metadata/datasets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active_version":   "2026.10.25-001",
				"previous_version": "2026.10.24-001",
				"snapshots": []map[string]any{
					{
						"snapshot_version":  "2026.10.25-001",
						"digest":            "sha256:abc123",
						"ruleset_version":   "v1",
						"published_at":      "2026-10-25T00:00:00Z",
						"ipv4_prefix_count": 950000,
						"ipv6_prefix_count": 220000,
					},
				},
			})
		case "/v1/feedback":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                   "fb_go_999",
				"prefix_or_ip":         "8.8.8.8",
				"role":                 "network_operator",
				"issue_type":           "wrong_country",
				"requested_correction": map[string]any{"country_code": "US"},
				"created_at":           "2026-10-25T10:00:00Z",
				"status":               "pending_review",
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"snapshot": map[string]any{
					"currentVersion":  "2026.10.25-001",
					"previousVersion": "2026.10.24-001",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := NewClient("ips_live_valid_key_12345", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	netRes, err := client.LookupNetwork(ctx, "8.8.8.0/24")
	if err != nil || netRes.QueriedCIDR != "8.8.8.0/24" || netRes.Record == nil || *netRes.Record.ASN != 15169 {
		t.Fatalf("LookupNetwork failed: %+v, err=%v", netRes, err)
	}

	callerRes, err := client.LookupCallerIP(ctx)
	if err != nil || callerRes.IP != "203.0.113.42" {
		t.Fatalf("LookupCallerIP failed: %+v, err=%v", callerRes, err)
	}

	metaRes, err := client.GetDatasetsMetadata(ctx)
	if err != nil || metaRes.ActiveVersion != "2026.10.25-001" || len(metaRes.Snapshots) != 1 {
		t.Fatalf("GetDatasetsMetadata failed: %+v, err=%v", metaRes, err)
	}

	fbRes, err := client.SubmitFeedback(ctx, FeedbackSubmissionInput{
		PrefixOrIP:          "8.8.8.8",
		Role:                FeedbackRoleNetworkOperator,
		IssueType:           FeedbackIssueWrongCountry,
		RequestedCorrection: map[string]any{"country_code": "US"},
	})
	if err != nil || fbRes.ID != "fb_go_999" {
		t.Fatalf("SubmitFeedback failed: %+v, err=%v", fbRes, err)
	}

	statusRes, err := client.GetStatus(ctx)
	if err != nil || statusRes.Status != "ok" || statusRes.CurrentVersion == nil || *statusRes.CurrentVersion != "2026.10.25-001" {
		t.Fatalf("GetStatus failed: %+v, err=%v", statusRes, err)
	}
}

func TestRetriesErrorsAndMemoryBounds(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRateLimitHeaders(w)
		switch r.URL.Path {
		case "/v1/ip/1.1.1.1":
			n := attempts.Add(1)
			if n == 1 {
				w.Header().Set("Retry-After", "0.005")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{"message": "Rate limit exceeded"})
				return
			}
			if n == 2 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"message": "Service unavailable"})
				return
			}
			_ = json.NewEncoder(w).Encode(makeMockIPRecord("1.1.1.1"))
		case "/v1/ip/8.8.4.4":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "Invalid API Key"})
		case "/v1/ip/9.9.9.9":
			// Oversized > 2 MiB response
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytesRepeat('x', MaxResponseBytes+64))
		}
	}))
	defer srv.Close()

	client, err := NewClient(
		"ips_live_valid_key_12345",
		WithBaseURL(srv.URL),
		WithRetryOptions(RetryOptions{
			MaxRetries:       3,
			BaseDelay:        5 * time.Millisecond,
			MaxDelay:         20 * time.Millisecond,
			RetryOnRateLimit: true,
		}),
		WithCacheOptions(CacheOptions{
			Enabled:    true,
			MaxEntries: 3,
			TTL:        time.Minute,
		}),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// 1. Retries on 429 and 503 then succeeds
	rec, err := client.LookupIP(ctx, "1.1.1.1")
	if err != nil || rec.IP != "1.1.1.1" || attempts.Load() != 3 {
		t.Fatalf("expected success after 3 attempts, got rec=%+v, err=%v, attempts=%d", rec, err, attempts.Load())
	}

	// 2. 401 Unauthorized fails immediately without retrying
	_, authErr := client.LookupIP(ctx, "8.8.4.4")
	if !IsAuthError(authErr) {
		t.Fatalf("expected AuthError on 401, got %v", authErr)
	}

	// 3. Oversized > 2 MiB response rejected
	_, sizeErr := client.LookupIP(ctx, "9.9.9.9")
	apiErr, ok := sizeErr.(*APIError)
	if !ok || apiErr.Code != ErrCodeResponseTooLarge {
		t.Fatalf("expected ErrCodeResponseTooLarge, got %v", sizeErr)
	}

	// 4. Bounded LRU cache eviction (maxEntries = 3)
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		client.ipCache.Set(ip, &IPLookupResponse{IP: ip})
	}
	if size := client.GetCacheStats().Size; size > 3 {
		t.Fatalf("expected LRU cache size <= 3, got %d", size)
	}
}

func bytesRepeat(b byte, n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
