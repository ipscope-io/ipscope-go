// Package ipscope provides the official, zero-dependency, type-safe Go server-side SDK
// for the IPScope IP Intelligence Platform.
//
// Scope Notice: This SDK is intentionally scoped strictly to IP intelligence,
// network prefix, dataset metadata, feedback, and health operations. It contains
// zero account, billing, wallet, or key-management operations.
package ipscope

import "time"

// IPFamily represents the IP protocol version (4 or 6).
type IPFamily int

const (
	IPFamilyV4 IPFamily = 4
	IPFamilyV6 IPFamily = 6
)

// LocationType classifies the geographic precision/nature of an IP location.
type LocationType string

const (
	LocationTypePhysical LocationType = "physical"
	LocationTypeDeclared LocationType = "declared"
	LocationTypeVirtual  LocationType = "virtual"
	LocationTypeAnycast  LocationType = "anycast"
	LocationTypeUnknown  LocationType = "unknown"
)

// AnonymizerType classifies the type of anonymizer or relay service detected.
type AnonymizerType string

const (
	AnonymizerTypeVPN               AnonymizerType = "vpn"
	AnonymizerTypeProxy             AnonymizerType = "proxy"
	AnonymizerTypeTorExit           AnonymizerType = "tor_exit"
	AnonymizerTypeTorRelay          AnonymizerType = "tor_relay"
	AnonymizerTypeHostingProxy      AnonymizerType = "hosting_proxy"
	AnonymizerTypeApplePrivateRelay AnonymizerType = "apple_private_relay"
	AnonymizerTypeOtherRelay        AnonymizerType = "other_relay"
	AnonymizerTypeNone              AnonymizerType = "none"
	AnonymizerTypeUnknown           AnonymizerType = "unknown"
)

// ConnectionType classifies the network access type.
type ConnectionType string

const (
	ConnectionTypeResidential ConnectionType = "residential"
	ConnectionTypeMobile      ConnectionType = "mobile"
	ConnectionTypeBusiness    ConnectionType = "business"
	ConnectionTypeHosting     ConnectionType = "hosting"
	ConnectionTypeEducation   ConnectionType = "education"
	ConnectionTypeGovernment  ConnectionType = "government"
	ConnectionTypeUnknown     ConnectionType = "unknown"
)

// FeedbackRole identifies the role of the submitter in a correction feedback request.
type FeedbackRole string

const (
	FeedbackRoleNetworkOperator FeedbackRole = "network_operator"
	FeedbackRoleResearcher      FeedbackRole = "researcher"
	FeedbackRoleEndUser         FeedbackRole = "end_user"
)

// FeedbackIssueType identifies the category of a correction feedback request.
type FeedbackIssueType string

const (
	FeedbackIssueWrongCountry     FeedbackIssueType = "wrong_country"
	FeedbackIssueWrongCity        FeedbackIssueType = "wrong_city"
	FeedbackIssueFalsePositiveVPN FeedbackIssueType = "false_positive_vpn"
	FeedbackIssueFalseNegativeVPN FeedbackIssueType = "false_negative_vpn"
	FeedbackIssueWrongASN         FeedbackIssueType = "wrong_asn"
	FeedbackIssueOther            FeedbackIssueType = "other"
)

// GeoResponseBlock holds geographic classification and confidence for an IP address.
type GeoResponseBlock struct {
	CountryCode         *string      `json:"country_code"`
	Subdivision         *string      `json:"subdivision,omitempty"`
	City                *string      `json:"city"`
	Timezone            *string      `json:"timezone,omitempty"`
	LocationType        LocationType `json:"location_type"`
	Confidence          float64      `json:"confidence"`
	AccuracyRadiusKM    *float64     `json:"accuracy_radius_km,omitempty"`
	DeclaredCountryCode *string      `json:"declared_country_code,omitempty"`
	PhysicalCountryCode *string      `json:"physical_country_code,omitempty"`
	IsVirtualLocation   *bool        `json:"is_virtual_location,omitempty"`
}

// NetworkResponseBlock holds Autonomous System and network operator details.
type NetworkResponseBlock struct {
	ASN          *int    `json:"asn"`
	Organization *string `json:"organization"`
}

// SecurityResponseBlock holds security, hosting, and anonymity classification.
type SecurityResponseBlock struct {
	IsVPN          *bool          `json:"is_vpn"`
	IsHosting      *bool          `json:"is_hosting"`
	IsTorExit      *bool          `json:"is_tor_exit"`
	IsProxy        *bool          `json:"is_proxy"`
	AnonymizerType AnonymizerType `json:"anonymizer_type"`
	Confidence     float64        `json:"confidence"`
	ReasonCodes    []string       `json:"reason_codes,omitempty"`
}

// ConnectionResponseBlock holds optional connection context when licensed.
type ConnectionResponseBlock struct {
	ConnectionType ConnectionType `json:"connection_type"`
	IsResidential  *bool          `json:"is_residential"`
	IsMobile       *bool          `json:"is_mobile"`
	IsBusiness     *bool          `json:"is_business"`
	IsHosting      *bool          `json:"is_hosting"`
}

// SecurityExtensionsResponseBlock holds optional security extensions telemetry when licensed.
type SecurityExtensionsResponseBlock struct {
	AbuseVelocityScore      *float64 `json:"abuse_velocity_score"`
	IsKnownScanner          *bool    `json:"is_known_scanner"`
	ObservationRecencyHours *float64 `json:"observation_recency_hours"`
}

// IPLookupResponse represents the canonical single IP lookup response (`GET /v1/ip/:ip` and `GET /v1/ip/me`).
type IPLookupResponse struct {
	IP                 string                           `json:"ip"`
	IPVersion          IPFamily                         `json:"ip_version"`
	MatchedNetwork     *string                          `json:"matched_network"`
	Geo                GeoResponseBlock                 `json:"geo"`
	Network            NetworkResponseBlock             `json:"network"`
	Security           SecurityResponseBlock            `json:"security"`
	Connection         *ConnectionResponseBlock         `json:"connection,omitempty"`
	SecurityExtensions *SecurityExtensionsResponseBlock `json:"security_extensions,omitempty"`
	DatasetVersion     string                           `json:"dataset_version"`
	UpdatedAt          *string                          `json:"updated_at"`
}

// BatchLookupResponse represents the batch IP lookup response (`POST /v1/ip/batch`).
type BatchLookupResponse struct {
	DatasetVersion string              `json:"dataset_version"`
	Count          int                 `json:"count"`
	Results        []*IPLookupResponse `json:"results"`
}

// CanonicalNetworkPrefixRecord represents a canonical network prefix record in `GET /v1/networks/:prefix/:length`.
type CanonicalNetworkPrefixRecord struct {
	Prefix         string          `json:"prefix"`
	Family         IPFamily        `json:"family"`
	ASN            *int            `json:"asn"`
	Organization   *string         `json:"organization"`
	CountryCode    *string         `json:"country_code"`
	City           *string         `json:"city"`
	LocationType   *LocationType   `json:"location_type"`
	IsVPN          *bool           `json:"is_vpn"`
	IsHosting      *bool           `json:"is_hosting"`
	IsTorExit      *bool           `json:"is_tor_exit"`
	IsProxy        *bool           `json:"is_proxy"`
	AnonymizerType *AnonymizerType `json:"anonymizer_type"`
}

// NetworkPrefixLookupResponse represents the CIDR network lookup response (`GET /v1/networks/:prefix/:length`).
type NetworkPrefixLookupResponse struct {
	QueriedCIDR    string                        `json:"queried_cidr"`
	Family         IPFamily                      `json:"family"`
	DatasetVersion string                        `json:"dataset_version"`
	Record         *CanonicalNetworkPrefixRecord `json:"record"`
}

// DatasetSnapshotSummary represents a single dataset snapshot summary in `GET /v1/metadata/datasets`.
type DatasetSnapshotSummary struct {
	SnapshotVersion string `json:"snapshot_version"`
	Digest          string `json:"digest"`
	RulesetVersion  string `json:"ruleset_version"`
	PublishedAt     string `json:"published_at"`
	IPv4PrefixCount int    `json:"ipv4_prefix_count"`
	IPv6PrefixCount int    `json:"ipv6_prefix_count"`
}

// DatasetsMetadataResponse represents the response from `GET /v1/metadata/datasets`.
type DatasetsMetadataResponse struct {
	ActiveVersion   string                   `json:"active_version"`
	PreviousVersion *string                  `json:"previous_version"`
	Snapshots       []DatasetSnapshotSummary `json:"snapshots"`
}

// FeedbackSubmissionInput represents the input payload for `POST /v1/feedback`.
type FeedbackSubmissionInput struct {
	PrefixOrIP          string            `json:"prefix_or_ip"`
	Role                FeedbackRole      `json:"role"`
	IssueType           FeedbackIssueType `json:"issue_type"`
	RequestedCorrection map[string]any    `json:"requested_correction"`
	EvidenceURLs        []string          `json:"evidence_urls,omitempty"`
}

// FeedbackSubmissionResponse represents the response from `POST /v1/feedback`.
type FeedbackSubmissionResponse struct {
	ID                  string            `json:"id"`
	PrefixOrIP          string            `json:"prefix_or_ip"`
	Role                FeedbackRole      `json:"role"`
	IssueType           FeedbackIssueType `json:"issue_type"`
	RequestedCorrection map[string]any    `json:"requested_correction"`
	CreatedAt           string            `json:"created_at"`
	Status              string            `json:"status"`
	EvidenceURLs        []string          `json:"evidence_urls,omitempty"`
}

// ServiceSnapshotInfo holds active/previous dataset versions inside `GET /v1/status`.
type ServiceSnapshotInfo struct {
	CurrentVersion  *string `json:"currentVersion"`
	PreviousVersion *string `json:"previousVersion"`
}

// ServiceStatusResponse represents the public health status response (`GET /v1/status`).
type ServiceStatusResponse struct {
	Status          string               `json:"status"`
	Snapshot        *ServiceSnapshotInfo `json:"snapshot,omitempty"`
	CurrentVersion  *string              `json:"-"`
	PreviousVersion *string              `json:"-"`
}

// RateLimitMetadata holds parsed user-scoped rate-limit headers returned by `@ipscope/api`.
type RateLimitMetadata struct {
	LimitPerMinute    *int
	Remaining         *int
	ResetEpochSeconds *int64
	Scope             string
	BurstCapacity     *int
	RateLimitRPS      *int
}

// ResultWithMeta wraps a typed API response with HTTP status and rate-limit metadata.
type ResultWithMeta[T any] struct {
	Data      T
	Status    int
	RateLimit RateLimitMetadata
	FromCache bool
}

// CacheStats provides telemetry for the in-memory O(1) LRU + TTL cache.
type CacheStats struct {
	Enabled               bool
	Size                  int
	MaxEntries            int
	TTL                   time.Duration
	Hits                  uint64
	Misses                uint64
	CoalescedInFlightHits uint64
}

// RetryOptions configures automatic retry behavior on 429 and transient 502/503/504 errors.
type RetryOptions struct {
	MaxRetries       int
	BaseDelay        time.Duration
	MaxDelay         time.Duration
	RetryOnRateLimit bool
}

// CacheOptions configures the bounded in-memory O(1) LRU + TTL cache (`< 400 KB` default RAM ceiling).
type CacheOptions struct {
	Enabled    bool
	MaxEntries int
	TTL        time.Duration
}

// RequestOptions allows per-request overrides such as cache bypass or custom headers.
type RequestOptions struct {
	BypassCache bool
	Headers     map[string]string
}
