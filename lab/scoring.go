package lab

import (
	"fmt"
	"math"
	"time"
)

func ScoreAlert(alert *AggregateAlert, cfg ScoringConfig) {
	evidence, available := evidenceScore(*alert)
	contributions := []ScoreContribution{
		contribution("rita_evidence", evidence, cfg.RITAEvidenceWeight, available, "native RITA evidence for this detection type"),
		assetContribution(alert.Asset, cfg.AssetImportanceWeight),
		contribution("threat_intel", boolScore(alert.ThreatIntelHit), cfg.ThreatIntelWeight, true, "RITA threat-intel hit state"),
		persistenceContribution(*alert, cfg),
		rarityContribution(*alert, cfg.RarityWeight),
	}

	preAllowlist := 0.0
	for _, item := range contributions {
		preAllowlist += item.SignedContribution
	}
	if alert.Allowlist.Matched {
		reduction := clamp(alert.Allowlist.Rule.ScoreReduction)
		contributions = append(contributions, ScoreContribution{
			Name:               "allowlist_reduction",
			RawValue:           reduction,
			NormalizedValue:    reduction,
			SignedContribution: -reduction,
			Status:             "allowlist_reduction",
			Reason:             alert.Allowlist.Rule.Reason,
		})
	}

	alert.PreAllowlistScore = clamp(preAllowlist)
	if alert.Allowlist.Matched {
		preAllowlist -= clamp(alert.Allowlist.Rule.ScoreReduction)
	}
	alert.LabPriorityScore = 100 * clamp(preAllowlist)
	alert.ScoreBreakdown = contributions
}

func evidenceScore(alert AggregateAlert) (float64, bool) {
	switch alert.DetectionType {
	case DetectionBeacon:
		return clamp(maxNative(alert.NativeEvidence, func(e NativeEvidence) float64 { return max(e.BeaconThreatScore, e.BeaconScore) })), true
	case DetectionLongConnection:
		return clamp(maxNative(alert.NativeEvidence, func(e NativeEvidence) float64 { return e.LongConnectionScore })), true
	case DetectionStrobe:
		return clamp(maxNative(alert.NativeEvidence, func(e NativeEvidence) float64 { return e.StrobeScore })), true
	case DetectionDNSC2:
		return clamp(maxNative(alert.NativeEvidence, func(e NativeEvidence) float64 { return e.DNSScore })), true
	case DetectionThreatIntelOnly:
		return clamp(maxNative(alert.NativeEvidence, func(e NativeEvidence) float64 { return e.ThreatIntelScore })), true
	default:
		return 0, false
	}
}

func maxNative(evidence []NativeEvidence, value func(NativeEvidence) float64) float64 {
	var best float64
	for _, item := range evidence {
		best = max(best, value(item))
	}
	return best
}

func contribution(name string, raw, weight float64, available bool, reason string) ScoreContribution {
	status := "applied"
	if !available {
		status = "not_available"
	}
	normalized := clamp(raw)
	return ScoreContribution{
		Name:               name,
		RawValue:           raw,
		NormalizedValue:    normalized,
		Weight:             weight,
		SignedContribution: normalized * weight,
		Status:             status,
		Reason:             reason,
	}
}

func assetContribution(asset AssetMatch, weight float64) ScoreContribution {
	if !asset.Matched {
		return contribution("asset_importance", 0, weight, false, "source asset is not tagged")
	}
	return contribution("asset_importance", float64(asset.Asset.Importance)/100, weight, true, "matched asset "+asset.Asset.AssetID)
}

func persistenceContribution(alert AggregateAlert, cfg ScoringConfig) ScoreContribution {
	count := alert.ConnectionCount
	span := alert.LastSeen.Sub(alert.FirstSeen)
	if alert.DetectionType == DetectionDNSC2 && alert.DNSFeatures.Available {
		count = alert.DNSFeatures.QueryCount
		span = alert.DNSFeatures.LastSeen.Sub(alert.DNSFeatures.FirstSeen)
	}
	countComponent := clamp(float64(count) / float64(cfg.PersistenceCountTarget))
	durationComponent := clamp(span.Minutes() / cfg.PersistenceDurationMins)
	return contribution("persistence", (countComponent+durationComponent)/2, cfg.PersistenceWeight, true, fmt.Sprintf("%d events across %s", count, span.Round(time.Second)))
}

func rarityContribution(alert AggregateAlert, weight float64) ScoreContribution {
	var prevalence float64
	available := false
	for _, evidence := range alert.NativeEvidence {
		if evidence.NetworkSize > 0 && evidence.Prevalence >= 0 {
			prevalence = evidence.Prevalence
			available = true
			break
		}
	}
	if !available {
		return contribution("rarity", 0, weight, false, "RITA prevalence is unavailable")
	}
	return contribution("rarity", 1-clamp(prevalence), weight, true, "inverse RITA prevalence")
}

func boolScore(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func clamp(value float64) float64 {
	return math.Max(0, math.Min(1, value))
}

func max(left, right float64) float64 {
	return math.Max(left, right)
}
