// Package lab adds asset-aware, explainable reporting on top of RITA analysis data.
package lab

import (
	"net"
	"time"
)

const (
	DetectionBeacon          = "beacon"
	DetectionLongConnection  = "long_connection"
	DetectionStrobe          = "strobe"
	DetectionDNSC2           = "dns_c2"
	DetectionThreatIntelOnly = "threat_intel_only"

	DestinationDomain       = "domain"
	DestinationIPFallback   = "ip_fallback"
	DestinationUnattributed = "unattributed"
)

type LabConfig struct {
	SchemaVersion string           `json:"schema_version"`
	Assets        []Asset          `json:"assets"`
	Allowlists    Allowlists       `json:"allowlists"`
	Scoring       ScoringConfig    `json:"scoring"`
	Reporting     ReportingConfig  `json:"reporting"`
	DNSFeatures   DNSFeatureConfig `json:"dns_features"`
}

type Asset struct {
	CIDR        string `json:"cidr"`
	AssetID     string `json:"asset_id"`
	AssetType   string `json:"asset_type"`
	Owner       string `json:"owner"`
	Importance  int    `json:"importance"`
	NetworkZone string `json:"network_zone"`

	network *net.IPNet
	prefix  int
}

type Allowlists struct {
	Domains []AllowlistRule `json:"domains"`
}

type AllowlistRule struct {
	Pattern        string  `json:"pattern"`
	ScoreReduction float64 `json:"score_reduction"`
	Reason         string  `json:"reason"`
	Enabled        bool    `json:"enabled"`
}

type ScoringConfig struct {
	Version                 string  `json:"version"`
	RITAEvidenceWeight      float64 `json:"rita_evidence_weight"`
	AssetImportanceWeight   float64 `json:"asset_importance_weight"`
	ThreatIntelWeight       float64 `json:"threat_intel_weight"`
	PersistenceWeight       float64 `json:"persistence_weight"`
	RarityWeight            float64 `json:"rarity_weight"`
	PersistenceCountTarget  uint64  `json:"persistence_count_target"`
	PersistenceDurationMins float64 `json:"persistence_duration_minutes"`
}

type ReportingConfig struct {
	DefaultWindow string `json:"default_window"`
}

type DNSFeatureConfig struct {
	Enabled bool `json:"enabled"`
}

type NativeEvidence struct {
	Hash                string
	ImportID            string
	SourceIP            net.IP
	DestinationIP       net.IP
	FQDN                string
	Count               uint64
	LastSeen            time.Time
	FirstSeen           time.Time
	BeaconScore         float64
	BeaconThreatScore   float64
	LongConnectionScore float64
	StrobeScore         float64
	DNSScore            float64
	ThreatIntelHit      bool
	ThreatIntelScore    float64
	Prevalence          float64
	NetworkSize         uint64
	BaseScore           float64
	TotalModifierScore  float64
	NativeFinalScore    float64
	Modifiers           []Modifier
}

type Modifier struct {
	Name  string  `json:"name"`
	Value string  `json:"value"`
	Score float64 `json:"score"`
}

type DNSEvent struct {
	Timestamp        time.Time
	SourceIP         net.IP
	Domain           string
	Query            string
	ResponseCodeName string
}

type DNSFeatures struct {
	QueryCount              uint64    `json:"query_count"`
	UniqueEncodedLabels     uint64    `json:"unique_encoded_labels"`
	AverageLabelLength      float64   `json:"average_label_length"`
	MaximumLabelLength      int       `json:"maximum_label_length"`
	LabelEntropyBitsPerByte float64   `json:"label_entropy_bits_per_byte"`
	QueryFrequencyPerMinute float64   `json:"query_frequency_per_minute"`
	NXDOMAINCount           uint64    `json:"nxdomain_count"`
	NXDOMAINRatio           float64   `json:"nxdomain_ratio"`
	FirstSeen               time.Time `json:"first_seen"`
	LastSeen                time.Time `json:"last_seen"`
	Available               bool      `json:"available"`
}

type AssetMatch struct {
	Asset   Asset `json:"asset"`
	Matched bool  `json:"matched"`
}

type AllowlistMatch struct {
	Rule    AllowlistRule `json:"rule"`
	Matched bool          `json:"matched"`
}

type ScoreContribution struct {
	Name               string  `json:"name"`
	RawValue           float64 `json:"raw_value"`
	NormalizedValue    float64 `json:"normalized_value"`
	Weight             float64 `json:"weight"`
	SignedContribution float64 `json:"signed_contribution"`
	Status             string  `json:"status"`
	Reason             string  `json:"reason"`
}

type AggregateAlert struct {
	AlertID           string
	WindowStart       time.Time
	WindowEnd         time.Time
	SourceIP          net.IP
	Destination       string
	DestinationKind   string
	DetectionType     string
	FirstSeen         time.Time
	LastSeen          time.Time
	ConnectionCount   uint64
	DNSQueryCount     uint64
	BeaconScore       float64
	DNSScore          float64
	ThreatIntelHit    bool
	Asset             AssetMatch
	Allowlist         AllowlistMatch
	NativeEvidence    []NativeEvidence
	DNSFeatures       DNSFeatures
	ScoreBreakdown    []ScoreContribution
	PreAllowlistScore float64
	LabPriorityScore  float64
}

type EvaluationResult struct {
	ImportStartedAt  time.Time
	ReportDuration   time.Duration
	ImportedRecords  uint64
	AggregatedAlerts int
	Status           string
}

type Report struct {
	Database       string
	GeneratedAt    time.Time
	From           time.Time
	To             time.Time
	Window         time.Duration
	ConfigSHA256   string
	ScoringVersion string
	Alerts         []AggregateAlert
	Evaluation     *EvaluationResult
}
