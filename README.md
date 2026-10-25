# `ipscope-go` — Official IPScope Server-Side Go SDK

Official zero-dependency, concurrency-safe, strictly typed server-side **Go SDK** (`github.com/ipscope/ipscope-go`) for the **IPScope IP Intelligence Platform**.

> **Scope Notice:** This SDK is intentionally scoped strictly to **IP intelligence, network prefix, dataset metadata, feedback, and health operations**. It contains **zero account, billing, wallet, or key-management operations**, making it safe to deploy in production backend microservices, workers, and API gateways.

---

## Features

- **Zero External Dependencies**: Built purely on the Go 1.23+ standard library (`net/http`, `net/netip`, `context`, `iter`, `container/list`, `sync`).
- **Concurrency-Safe & Singleflight Request Coalescing**:
  - Thread-safe O(1) LRU + TTL cache (`MaxEntries: 512` default, `< 400 KB` heap footprint).
  - Concurrent goroutines looking up the same IP coalesce into a single in-flight HTTP request with guaranteed `defer` cleanup.
- **Memory-Safe & Zero Goroutine/Socket Leaks**:
  - Uses zero-allocation `net/netip` (`netip.ParseAddr`, `netip.ParsePrefix`) for IPv4/IPv6 and CIDR validation.
  - Enforces a hard `2 MiB` (`MaxResponseBytes`) response body ceiling via `io.LimitReader` and drains/closes `resp.Body` in `defer` so pooled `http.Transport` keep-alive connections are always reused cleanly.
  - Uses `time.NewTimer` with `defer timer.Stop()` for context-aware retry backoff (never leaks `time.After` timers).
  - `LookupBatchStream` returns a Go 1.23+ `iter.Seq2[*BatchLookupResponse, error]` iterator for processing 10,000+ IPs in constant `O(chunk)` RAM.

---

## Installation

```bash
go get github.com/ipscope/ipscope-go
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ipscope/ipscope-go"
)

func main() {
	client, err := ipscope.NewClient(
		"ips_live_your_api_key_here",
		ipscope.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// 1. Single IPv4 or IPv6 lookup (cached automatically in LRU cache & singleflight-coalesced)
	ipInfo, err := client.LookupIP(ctx, "8.8.8.8")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ipInfo.IP, *ipInfo.Geo.CountryCode, *ipInfo.Network.ASN)

	// 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
	batch, err := client.LookupBatch(ctx, []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"})
	if err != nil {
		log.Fatal(err)
	}
	for _, record := range batch.Results {
		fmt.Println(record.IP, *record.Network.Organization)
	}

	// 3. Chunked batch lookup for >100 IPs with bounded goroutine concurrency (e.g. 4 workers)
	largeBatch, err := client.LookupBatchChunked(ctx, []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}, 4)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Resolved:", largeBatch.Count)

	// 4. Constant-RAM streaming iterator (`iter.Seq2`) for 10,000+ IPs
	for chunk, err := range client.LookupBatchStream(ctx, []string{"8.8.8.8", "1.1.1.1"}) {
		if err != nil {
			log.Fatal(err)
		}
		for _, record := range chunk.Results {
			fmt.Println("Streamed:", record.IP)
		}
	}

	// 5. Network CIDR prefix lookup
	prefix, err := client.LookupNetwork(ctx, "8.8.8.0/24")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(prefix.QueriedCIDR, prefix.DatasetVersion)
}
```

---

## Error Handling

```go
ipInfo, err := client.LookupIP(ctx, "8.8.8.8")
if err != nil {
	switch {
	case ipscope.IsValidationError(err):
		// Invalid IP / CIDR / batch size before any network request is made
		fmt.Println("Validation error:", err)
	case ipscope.IsAuthError(err):
		// 401 Unauthorized or 403 Forbidden
		fmt.Println("Authentication error:", err)
	case ipscope.IsRateLimitError(err):
		// 429 Too Many Requests after retries exhausted
		fmt.Println("Rate limited:", err)
	case ipscope.IsTimeoutError(err):
		// Context deadline or per-request timeout exceeded
		fmt.Println("Timeout:", err)
	default:
		fmt.Println("API error:", err)
	}
}
```
