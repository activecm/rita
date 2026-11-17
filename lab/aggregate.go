package lab

import (
	"fmt"
	"net"
	"sort"
	"time"
)

func DetectionTypes(evidence NativeEvidence) []string {
	types := make([]string, 0, 5)
	if evidence.BeaconThreatScore > 0 || evidence.BeaconScore > 0 {
		types = append(types, DetectionBeacon)
	}
	if evidence.LongConnectionScore > 0 {
		types = append(types, DetectionLongConnection)
	}
	if evidence.StrobeScore > 0 {
		types = append(types, DetectionStrobe)
	}
	if evidence.DNSScore > 0 {
		types = append(types, DetectionDNSC2)
	}
	if evidence.ThreatIntelHit && len(types) == 0 {
		types = append(types, DetectionThreatIntelOnly)
	}
	return types
}

func AggregateEvidence(evidence []NativeEvidence, events []DNSEvent, cfg *LabConfig, window time.Duration) ([]AggregateAlert, error) {
	if cfg == nil {
		return nil, fmt.Errorf("lab configuration is nil")
	}
	if window <= 0 {
		return nil, ErrInvalidWindow
	}
	alerts := make(map[string]*AggregateAlert)
	for _, item := range evidence {
		for _, detectionType := range DetectionTypes(item) {
			if detectionType == DetectionDNSC2 && isUnattributedSource(item.SourceIP) {
				// RITA's DNS score is domain-level evidence. A raw DNS query for the
				// same domain does not establish that each querying host triggered the
				// native score, so retain the result as explicitly unattributed.
				item.SourceIP = nil
			}
			if err := addEvidenceAlert(alerts, item, detectionType, item.LastSeen, cfg, window); err != nil {
				return nil, err
			}
		}
	}

	result := make([]AggregateAlert, 0, len(alerts))
	for _, alert := range alerts {
		if alert.DetectionType == DetectionDNSC2 && alert.DestinationKind == DestinationDomain && !isUnattributedSource(alert.SourceIP) {
			dnsEvents := DNSFeatureEventsForWindow(events, alert.SourceIP.String(), alert.Destination, alert.WindowStart, alert.WindowEnd)
			alert.DNSFeatures = CalculateDNSFeatures(dnsEvents, alert.Destination)
			alert.DNSQueryCount = alert.DNSFeatures.QueryCount
			if alert.DNSFeatures.Available {
				alert.FirstSeen = alert.DNSFeatures.FirstSeen
				alert.LastSeen = alert.DNSFeatures.LastSeen
			}
		}
		ScoreAlert(alert, cfg.Scoring)
		result = append(result, *alert)
	}
	SortAlerts(result)
	return result, nil
}

func addEvidenceAlert(alerts map[string]*AggregateAlert, item NativeEvidence, detectionType string, timestamp time.Time, cfg *LabConfig, window time.Duration) error {
	destination, kind := DestinationFor(item)
	if item.SourceIP == nil && detectionType == DetectionDNSC2 {
		kind = DestinationUnattributed
	}
	start, end, err := WindowFor(timestamp, window)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", item.SourceIP, destination, detectionType, start)
	alert, exists := alerts[key]
	if !exists {
		alert = &AggregateAlert{
			AlertID:         AlertID(item.SourceIP, destination, detectionType, start),
			WindowStart:     start,
			WindowEnd:       end,
			SourceIP:        item.SourceIP,
			Destination:     destination,
			DestinationKind: kind,
			DetectionType:   detectionType,
			FirstSeen:       item.FirstSeen,
			LastSeen:        item.LastSeen,
			Asset:           MatchAsset(cfg.Assets, item.SourceIP),
			Allowlist:       MatchAllowlist(cfg.Allowlists.Domains, destination),
		}
		alerts[key] = alert
	}
	aggregateInto(alert, item)
	return nil
}

func isUnattributedSource(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified()
}

func aggregateInto(alert *AggregateAlert, item NativeEvidence) {
	if alert.FirstSeen.IsZero() || (!item.FirstSeen.IsZero() && item.FirstSeen.Before(alert.FirstSeen)) {
		alert.FirstSeen = item.FirstSeen
	}
	if item.LastSeen.After(alert.LastSeen) {
		alert.LastSeen = item.LastSeen
	}
	alert.ConnectionCount += item.Count
	if item.BeaconScore > alert.BeaconScore {
		alert.BeaconScore = item.BeaconScore
	}
	if item.DNSScore > alert.DNSScore {
		alert.DNSScore = item.DNSScore
	}
	alert.ThreatIntelHit = alert.ThreatIntelHit || item.ThreatIntelHit
	alert.NativeEvidence = append(alert.NativeEvidence, item)
}

func SortAlerts(alerts []AggregateAlert) {
	sort.Slice(alerts, func(i, j int) bool {
		left, right := alerts[i], alerts[j]
		if left.LabPriorityScore != right.LabPriorityScore {
			return left.LabPriorityScore > right.LabPriorityScore
		}
		if !left.WindowStart.Equal(right.WindowStart) {
			return left.WindowStart.Before(right.WindowStart)
		}
		if left.SourceIP.String() != right.SourceIP.String() {
			return left.SourceIP.String() < right.SourceIP.String()
		}
		if left.Destination != right.Destination {
			return left.Destination < right.Destination
		}
		if left.DetectionType != right.DetectionType {
			return left.DetectionType < right.DetectionType
		}
		return left.AlertID < right.AlertID
	})
}
