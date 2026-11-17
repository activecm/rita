package lab

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testConfig(t *testing.T) *LabConfig {
	t.Helper()
	cfg := &LabConfig{
		SchemaVersion: "v1",
		Assets: []Asset{
			{CIDR: "10.0.0.0/8", AssetID: "network", AssetType: "network", Owner: "security", Importance: 20, NetworkZone: "lab"},
			{CIDR: "10.1.2.3", AssetID: "critical-host", AssetType: "server", Owner: "security", Importance: 90, NetworkZone: "restricted"},
		},
		Allowlists: Allowlists{Domains: []AllowlistRule{{Pattern: "*.updates.example.test", ScoreReduction: .3, Reason: "controlled update service", Enabled: true}}},
		Scoring:    ScoringConfig{Version: "v1", RITAEvidenceWeight: .45, AssetImportanceWeight: .2, ThreatIntelWeight: .15, PersistenceWeight: .1, RarityWeight: .1, PersistenceCountTarget: 10, PersistenceDurationMins: 30},
		Reporting:  ReportingConfig{DefaultWindow: "30m"},
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestMatchAssetUsesLongestPrefix(t *testing.T) {
	cfg := testConfig(t)
	match := MatchAsset(cfg.Assets, net.ParseIP("10.1.2.3"))
	require.True(t, match.Matched)
	require.Equal(t, "critical-host", match.Asset.AssetID)

	unmatched := MatchAsset(cfg.Assets, net.ParseIP("192.0.2.1"))
	require.False(t, unmatched.Matched)
	require.Equal(t, "unclassified", unmatched.Asset.AssetID)
}

func TestAllowlistNormalizesDomains(t *testing.T) {
	cfg := testConfig(t)
	match := MatchAllowlist(cfg.Allowlists.Domains, "HOST.UPDATES.EXAMPLE.TEST.")
	require.True(t, match.Matched)
	require.Equal(t, .3, match.Rule.ScoreReduction)
}

func TestCalculateDNSFeatures(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	features := CalculateDNSFeatures([]DNSEvent{
		{Timestamp: start, Query: "abcd.tunnel.example.test", Domain: "tunnel.example.test", ResponseCodeName: "NXDOMAIN"},
		{Timestamp: start.Add(2 * time.Minute), Query: "efgh.tunnel.example.test", Domain: "tunnel.example.test", ResponseCodeName: "NOERROR"},
	}, "tunnel.example.test")
	require.True(t, features.Available)
	require.Equal(t, uint64(2), features.QueryCount)
	require.Equal(t, uint64(2), features.UniqueEncodedLabels)
	require.Equal(t, 4.0, features.AverageLabelLength)
	require.Equal(t, 4, features.MaximumLabelLength)
	require.Equal(t, .5, features.NXDOMAINRatio)
	require.Equal(t, 1.0, features.QueryFrequencyPerMinute)
	require.Greater(t, features.LabelEntropyBitsPerByte, 0.0)
}

func TestAggregateEvidenceScoresAndRetainsAllowlistedAlert(t *testing.T) {
	cfg := testConfig(t)
	lastSeen := time.Date(2026, 1, 1, 0, 15, 0, 0, time.UTC)
	alerts, err := AggregateEvidence([]NativeEvidence{{
		SourceIP: net.ParseIP("10.1.2.3"), FQDN: "host.updates.example.test.", Count: 10,
		FirstSeen: lastSeen.Add(-30 * time.Minute), LastSeen: lastSeen, BeaconScore: .8, BeaconThreatScore: .8,
		ThreatIntelHit: true, Prevalence: .2, NetworkSize: 20,
	}}, nil, cfg, 30*time.Minute)
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	alert := alerts[0]
	require.True(t, alert.Allowlist.Matched)
	require.Equal(t, "critical-host", alert.Asset.Asset.AssetID)
	require.Equal(t, uint64(10), alert.ConnectionCount)
	require.Greater(t, alert.PreAllowlistScore, alert.LabPriorityScore/100)
	require.Len(t, alert.ScoreBreakdown, 6)
}

func TestUnattributedDNSUsesRawDNSSource(t *testing.T) {
	cfg := testConfig(t)
	when := time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC)
	alerts, err := AggregateEvidence([]NativeEvidence{{
		SourceIP: net.ParseIP("::"), FQDN: "tunnel.example.test", DNSScore: .8, LastSeen: when, FirstSeen: when,
	}}, []DNSEvent{{
		Timestamp: when, SourceIP: net.ParseIP("10.1.2.3"), Domain: "tunnel.example.test", Query: "encoded.tunnel.example.test",
	}}, cfg, 30*time.Minute)
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	require.Nil(t, alerts[0].SourceIP)
	require.Equal(t, DestinationUnattributed, alerts[0].DestinationKind)
	require.Equal(t, uint64(0), alerts[0].DNSQueryCount)
}

func TestWindowAndAlertIDAreStable(t *testing.T) {
	timestamp := time.Date(2026, 1, 1, 0, 31, 0, 0, time.UTC)
	start, end, err := WindowFor(timestamp, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC), start)
	require.Equal(t, start.Add(30*time.Minute), end)
	first := AlertID(net.ParseIP("10.0.0.1"), "example.test", DetectionBeacon, start)
	require.Equal(t, first, AlertID(net.ParseIP("10.0.0.1"), "example.test", DetectionBeacon, start))
}
