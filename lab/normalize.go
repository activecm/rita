package lab

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"
)

func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func WindowFor(timestamp time.Time, window time.Duration) (time.Time, time.Time, error) {
	if window <= 0 {
		return time.Time{}, time.Time{}, ErrInvalidWindow
	}
	utc := timestamp.UTC()
	start := utc.Truncate(window)
	return start, start.Add(window), nil
}

func DestinationFor(evidence NativeEvidence) (string, string) {
	if domain := NormalizeDomain(evidence.FQDN); domain != "" {
		return domain, DestinationDomain
	}
	if evidence.DestinationIP != nil {
		return "ip:" + evidence.DestinationIP.String(), DestinationIPFallback
	}
	return "unattributed", DestinationUnattributed
}

func AlertID(sourceIP net.IP, destination, detectionType string, windowStart time.Time) string {
	input := strings.Join([]string{
		sourceIP.String(),
		destination,
		detectionType,
		windowStart.UTC().Format(time.RFC3339Nano),
	}, "\x00")
	digest := sha256.Sum256([]byte(input))
	return fmt.Sprintf("lab-%x", digest[:12])
}

// SignificantDomain is a deliberately conservative fallback for lab-side grouping.
// ClickHouse applies its public-suffix-aware function in queries; this fallback keeps
// Go-side synthetic fixtures deterministic without claiming full PSL semantics.
func SignificantDomain(query string) string {
	query = NormalizeDomain(query)
	labels := strings.Split(query, ".")
	if len(labels) < 3 {
		return query
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func EncodedLabel(query, domain string) string {
	query = NormalizeDomain(query)
	domain = NormalizeDomain(domain)
	if query == "" || domain == "" || query == domain || !strings.HasSuffix(query, "."+domain) {
		return ""
	}
	prefix := strings.TrimSuffix(query, "."+domain)
	return strings.Split(prefix, ".")[0]
}
