package lab

import (
	"math"
	"strings"
	"time"
)

func CalculateDNSFeatures(events []DNSEvent, domain string) DNSFeatures {
	if len(events) == 0 {
		return DNSFeatures{}
	}

	features := DNSFeatures{Available: true}
	domain = NormalizeDomain(domain)
	labels := make(map[string]struct{})
	bytes := make(map[byte]uint64)
	var byteCount, totalLength, labelCount uint64

	for _, event := range events {
		if domain != "" && NormalizeDomain(event.Domain) != domain {
			continue
		}
		if features.FirstSeen.IsZero() || event.Timestamp.Before(features.FirstSeen) {
			features.FirstSeen = event.Timestamp
		}
		if event.Timestamp.After(features.LastSeen) {
			features.LastSeen = event.Timestamp
		}
		features.QueryCount++
		if strings.EqualFold(event.ResponseCodeName, "NXDOMAIN") {
			features.NXDOMAINCount++
		}

		label := EncodedLabel(event.Query, domain)
		if label == "" {
			continue
		}
		labels[label] = struct{}{}
		length := len(label)
		labelCount++
		totalLength += uint64(length)
		if length > features.MaximumLabelLength {
			features.MaximumLabelLength = length
		}
		for _, b := range []byte(label) {
			bytes[b]++
			byteCount++
		}
	}

	features.UniqueEncodedLabels = uint64(len(labels))
	features.NXDOMAINRatio = float64(features.NXDOMAINCount) / float64(features.QueryCount)
	if features.LastSeen.After(features.FirstSeen) {
		minutes := features.LastSeen.Sub(features.FirstSeen).Minutes()
		if minutes > 0 {
			features.QueryFrequencyPerMinute = float64(features.QueryCount) / minutes
		}
	}
	if labelCount > 0 {
		features.AverageLabelLength = float64(totalLength) / float64(labelCount)
	}
	if byteCount > 0 {
		for _, count := range bytes {
			probability := float64(count) / float64(byteCount)
			features.LabelEntropyBitsPerByte -= probability * math.Log2(probability)
		}
	}
	return features
}

func DNSFeatureEventsForWindow(events []DNSEvent, source string, domain string, start, end time.Time) []DNSEvent {
	result := make([]DNSEvent, 0)
	for _, event := range events {
		if event.SourceIP.String() != source || event.Timestamp.Before(start) || !event.Timestamp.Before(end) || NormalizeDomain(event.Domain) != NormalizeDomain(domain) {
			continue
		}
		result = append(result, event)
	}
	return result
}
