package ipscope

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxSingleBatchSize is the maximum number of IPs allowed in a single `POST /v1/ip/batch` call.
const MaxSingleBatchSize = 100

// ValidateAPIKey validates and trims an IPScope API key, rejecting empty strings and control characters.
func ValidateAPIKey(rawKey string) (string, error) {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return "", &ValidationError{
			Field:   "apiKey",
			Message: "API key cannot be empty",
		}
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", &ValidationError{
			Field:   "apiKey",
			Message: "API key contains invalid control characters",
		}
	}
	return trimmed, nil
}

// ValidateIPAddress validates an IPv4 or IPv6 address using zero-allocation `net/netip`
// and returns the canonical lowercase string and protocol family (4 or 6).
func ValidateIPAddress(rawIP string) (string, IPFamily, error) {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" || strings.Contains(trimmed, "%") {
		return "", 0, &ValidationError{
			Field:   "ip",
			Message: fmt.Sprintf("invalid IPv4 or IPv6 address: %q", trimmed),
		}
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.IsValid() {
		return "", 0, &ValidationError{
			Field:   "ip",
			Message: fmt.Sprintf("invalid IPv4 or IPv6 address: %q", trimmed),
		}
	}
	if addr.Is6() {
		return addr.String(), IPFamilyV6, nil
	}
	return addr.String(), IPFamilyV4, nil
}

// ValidateCIDRPrefix validates a CIDR prefix (`<ip>/<prefixLength>`) using `net/netip`
// and returns `(maskedAddrString, prefixBits, family, canonicalCIDR, error)`.
func ValidateCIDRPrefix(rawCIDR string) (string, int, IPFamily, string, error) {
	trimmed := strings.TrimSpace(rawCIDR)
	if trimmed == "" || strings.Count(trimmed, "/") != 1 {
		return "", 0, 0, "", &ValidationError{
			Field:   "cidr",
			Message: fmt.Sprintf("invalid CIDR notation %q; expected \"<ip>/<prefixLength>\" (e.g. \"8.8.8.0/24\")", trimmed),
		}
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil || !prefix.IsValid() {
		return "", 0, 0, "", &ValidationError{
			Field:   "cidr",
			Message: fmt.Sprintf("invalid CIDR prefix: %q", trimmed),
		}
	}
	masked := prefix.Masked()
	addrStr := masked.Addr().String()
	bits := masked.Bits()
	family := IPFamilyV4
	if masked.Addr().Is6() {
		family = IPFamilyV6
	}
	return addrStr, bits, family, masked.String(), nil
}

// ValidateAndDeduplicateBatchIPs validates a slice of 1..maxBatchSize IPs and returns
// `(orderedNormalizedIPs, uniqueNormalizedIPs, error)`.
func ValidateAndDeduplicateBatchIPs(rawIPs []string, maxBatchSize int) ([]string, []string, error) {
	if len(rawIPs) == 0 {
		return nil, nil, &ValidationError{
			Field:   "ips",
			Message: "batch IPs slice must contain at least 1 IP address",
		}
	}
	if maxBatchSize > 0 && len(rawIPs) > maxBatchSize {
		return nil, nil, &ValidationError{
			Field:   "ips",
			Message: fmt.Sprintf("batch IPs length (%d) exceeds maximum single-request batch size (%d); use LookupBatchChunked or LookupBatchStream for larger lists", len(rawIPs), maxBatchSize),
		}
	}

	ordered := make([]string, len(rawIPs))
	seen := make(map[string]struct{}, len(rawIPs))
	unique := make([]string, 0, len(rawIPs))

	for i, raw := range rawIPs {
		canonical, _, err := ValidateIPAddress(raw)
		if err != nil {
			return nil, nil, err
		}
		ordered[i] = canonical
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			unique = append(unique, canonical)
		}
	}

	return ordered, unique, nil
}
