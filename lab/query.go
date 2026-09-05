package lab

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/activecm/rita/v5/database"
)

type evidenceRow struct {
	Hash                     string    `ch:"hash"`
	ImportID                 string    `ch:"import_id"`
	AnalyzedAt               time.Time `ch:"analyzed_at"`
	Src                      net.IP    `ch:"src"`
	Dst                      net.IP    `ch:"dst"`
	FQDN                     string    `ch:"fqdn"`
	Count                    uint64    `ch:"count"`
	LastSeen                 time.Time `ch:"last_seen"`
	FirstSeen                time.Time `ch:"first_seen_historical"`
	BeaconScore              float64   `ch:"beacon_score"`
	BeaconThreatScore        float64   `ch:"beacon_threat_score"`
	LongConnectionScore      float64   `ch:"long_conn_score"`
	StrobeScore              float64   `ch:"strobe_score"`
	DNSScore                 float64   `ch:"c2_over_dns_score"`
	ThreatIntelHit           bool      `ch:"threat_intel"`
	ThreatIntelScore         float64   `ch:"threat_intel_score"`
	Prevalence               float64   `ch:"prevalence"`
	NetworkSize              uint64    `ch:"network_size"`
	BaseScore                float64   `ch:"base_score"`
	PrevalenceScore          float64   `ch:"prevalence_score"`
	FirstSeenScore           float64   `ch:"first_seen_score"`
	ThreatIntelDataSizeScore float64   `ch:"threat_intel_data_size_score"`
	MissingHostHeaderScore   float64   `ch:"missing_host_header_score"`
	DNSDirectConnScore       float64   `ch:"c2_over_dns_direct_conn_score"`
	NativeFinalScore         float64   `ch:"native_final_score"`
}

type modifierRow struct {
	Hash     string  `ch:"hash"`
	ImportID string  `ch:"import_id"`
	Name     string  `ch:"modifier_name"`
	Value    string  `ch:"modifier_value"`
	Score    float64 `ch:"modifier_score"`
}

type dnsRow struct {
	Timestamp        time.Time `ch:"ts"`
	SourceIP         net.IP    `ch:"src"`
	Domain           string    `ch:"domain"`
	Query            string    `ch:"query"`
	ResponseCodeName string    `ch:"response_code_name"`
}

// QueryNativeEvidence reads the latest baseline snapshot for each RITA connection
// hash in the requested report range. Modifier rows are read separately from that
// exact snapshot, so neither history nor modifiers inflate native evidence counts.
func QueryNativeEvidence(db *database.DB, from, to time.Time) ([]NativeEvidence, error) {
	params := clickhouse.Parameters{
		"database": db.GetSelectedDB(),
		"from":     fmt.Sprint(from.UTC().Unix()),
		"to":       fmt.Sprint(to.UTC().Unix()),
	}
	ctx := db.QueryParameters(params)
	query := `--sql
		WITH latest AS (
			SELECT
				hash,
				tupleElement(snapshot, 1) AS import_id,
				tupleElement(snapshot, 2) AS last_seen,
				tupleElement(snapshot, 3) AS analyzed_at
			FROM (
				SELECT hash, argMax(tuple(import_id, last_seen, analyzed_at), tuple(last_seen, analyzed_at)) AS snapshot
				FROM {database:Identifier}.threat_mixtape
				WHERE modifier_name = ''
				  AND last_seen >= fromUnixTimestamp({from:Int64})
				  AND last_seen < fromUnixTimestamp({to:Int64})
				GROUP BY hash
			)
		)
		SELECT
			t.hash, t.import_id, t.analyzed_at, t.src, t.dst, t.fqdn, t.count, t.last_seen,
			t.first_seen_historical, t.beacon_score, t.beacon_threat_score,
			t.long_conn_score, t.strobe_score, t.c2_over_dns_score,
			t.threat_intel, t.threat_intel_score, t.prevalence, t.network_size,
			greatest(t.beacon_threat_score, t.long_conn_score, t.strobe_score, t.c2_over_dns_score, t.threat_intel_score) AS base_score,
			t.prevalence_score, t.first_seen_score, t.threat_intel_data_size_score,
			t.missing_host_header_score, t.c2_over_dns_direct_conn_score,
			greatest(t.beacon_threat_score, t.long_conn_score, t.strobe_score, t.c2_over_dns_score, t.threat_intel_score)
				+ t.prevalence_score + t.first_seen_score + t.missing_host_header_score
				+ t.threat_intel_data_size_score + t.c2_over_dns_direct_conn_score AS native_final_score
		FROM {database:Identifier}.threat_mixtape AS t
		INNER JOIN latest ON t.hash = latest.hash
			AND t.import_id = latest.import_id
			AND t.last_seen = latest.last_seen
			AND t.analyzed_at = latest.analyzed_at
		WHERE t.modifier_name = ''
		  AND t.last_seen >= fromUnixTimestamp({from:Int64})
		  AND t.last_seen < fromUnixTimestamp({to:Int64})
	`
	rows, err := db.Conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query RITA evidence: %w", err)
	}
	defer rows.Close()

	evidence := make([]NativeEvidence, 0)
	byKey := make(map[string]int)
	for rows.Next() {
		var row evidenceRow
		if err := rows.ScanStruct(&row); err != nil {
			return nil, fmt.Errorf("scan RITA evidence: %w", err)
		}
		item := NativeEvidence{
			Hash: row.Hash, ImportID: row.ImportID, SourceIP: row.Src, DestinationIP: row.Dst, FQDN: row.FQDN,
			Count: row.Count, LastSeen: row.LastSeen, FirstSeen: row.FirstSeen, BeaconScore: row.BeaconScore,
			BeaconThreatScore: row.BeaconThreatScore, LongConnectionScore: row.LongConnectionScore, StrobeScore: row.StrobeScore,
			DNSScore: row.DNSScore, ThreatIntelHit: row.ThreatIntelHit, ThreatIntelScore: row.ThreatIntelScore,
			Prevalence: row.Prevalence, NetworkSize: row.NetworkSize, BaseScore: row.BaseScore,
			NativeFinalScore: row.NativeFinalScore,
		}
		if item.FirstSeen.IsZero() {
			item.FirstSeen = item.LastSeen
		}
		byKey[evidenceKey(row.Hash, row.ImportID, row.LastSeen, row.AnalyzedAt)] = len(evidence)
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate RITA evidence: %w", err)
	}

	if err := queryModifiers(db, from, to, byKey, evidence); err != nil {
		return nil, err
	}
	return evidence, nil
}

func evidenceKey(hash, importID string, lastSeen, analyzedAt time.Time) string {
	return strings.Join([]string{hash, importID, lastSeen.UTC().Format(time.RFC3339Nano), analyzedAt.UTC().Format(time.RFC3339Nano)}, "\x00")
}

func queryModifiers(db *database.DB, from, to time.Time, indexes map[string]int, evidence []NativeEvidence) error {
	if len(indexes) == 0 {
		return nil
	}
	params := clickhouse.Parameters{
		"database": db.GetSelectedDB(),
		"from":     fmt.Sprint(from.UTC().Unix()),
		"to":       fmt.Sprint(to.UTC().Unix()),
	}
	ctx := db.QueryParameters(params)
	query := `--sql
		WITH latest AS (
			SELECT
				hash,
				tupleElement(snapshot, 1) AS import_id,
				tupleElement(snapshot, 2) AS last_seen,
				tupleElement(snapshot, 3) AS analyzed_at
			FROM (
				SELECT hash, argMax(tuple(import_id, last_seen, analyzed_at), tuple(last_seen, analyzed_at)) AS snapshot
				FROM {database:Identifier}.threat_mixtape
				WHERE modifier_name = ''
				  AND last_seen >= fromUnixTimestamp({from:Int64})
				  AND last_seen < fromUnixTimestamp({to:Int64})
				GROUP BY hash
			)
		)
		SELECT t.hash, t.import_id, t.modifier_name, t.modifier_value, t.modifier_score
		FROM {database:Identifier}.threat_mixtape AS t
		INNER JOIN latest ON t.hash = latest.hash
			AND t.import_id = latest.import_id
			AND t.last_seen = latest.last_seen
			AND t.analyzed_at = latest.analyzed_at
		WHERE t.modifier_name != ''
		  AND t.last_seen >= fromUnixTimestamp({from:Int64})
		  AND t.last_seen < fromUnixTimestamp({to:Int64})
	`
	rows, err := db.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("query RITA modifiers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row modifierRow
		if err := rows.ScanStruct(&row); err != nil {
			return fmt.Errorf("scan RITA modifier: %w", err)
		}
		var index int
		var ok bool
		// The SQL snapshot join leaves one baseline snapshot per hash/import pair;
		// modifier rows carry the same pair but not the baseline timestamps.
		for candidateKey, candidateIndex := range indexes {
			if strings.HasPrefix(candidateKey, row.Hash+"\x00"+row.ImportID+"\x00") {
				index, ok = candidateIndex, true
				break
			}
		}
		if !ok {
			continue
		}
		evidence[index].Modifiers = append(evidence[index].Modifiers, Modifier{Name: row.Name, Value: row.Value, Score: row.Score})
		evidence[index].TotalModifierScore += row.Score
		evidence[index].NativeFinalScore += row.Score
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate RITA modifiers: %w", err)
	}
	return nil
}

func QueryDNSEvents(db *database.DB, from, to time.Time, domains []string) ([]DNSEvent, error) {
	domains = normalizedDomains(domains)
	if len(domains) == 0 {
		return nil, nil
	}
	params := clickhouse.Parameters{
		"database": db.GetSelectedDB(),
		"from":     fmt.Sprint(from.UTC().Unix()),
		"to":       fmt.Sprint(to.UTC().Unix()),
		"domains":  clickHouseStringArray(domains),
	}
	ctx := db.QueryParameters(params)
	query := `--sql
		SELECT ts, src, lowerUTF8(trimRight(cutToFirstSignificantSubdomain(query), '.')) AS domain, query, response_code_name
		FROM {database:Identifier}.dns
		WHERE ts >= fromUnixTimestamp({from:Int64})
		  AND ts < fromUnixTimestamp({to:Int64})
		  AND lowerUTF8(trimRight(cutToFirstSignificantSubdomain(query), '.')) IN {domains:Array(String)}
	`
	rows, err := db.Conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query raw DNS evidence: %w", err)
	}
	defer rows.Close()
	events := make([]DNSEvent, 0)
	for rows.Next() {
		var row dnsRow
		if err := rows.ScanStruct(&row); err != nil {
			return nil, fmt.Errorf("scan raw DNS evidence: %w", err)
		}
		events = append(events, DNSEvent{Timestamp: row.Timestamp, SourceIP: row.SourceIP, Domain: NormalizeDomain(row.Domain), Query: row.Query, ResponseCodeName: row.ResponseCodeName})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate raw DNS evidence: %w", err)
	}
	return events, nil
}

func normalizedDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = NormalizeDomain(domain)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

// clickHouseStringArray returns a ClickHouse Array(String) literal for the
// driver's string-only named-parameter API. Values originate from database
// results but remain escaped rather than interpolated into the SQL text.
func clickHouseStringArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ReplaceAll(value, "\\", "\\\\")
		value = strings.ReplaceAll(value, "'", "\\'")
		quoted = append(quoted, "'"+value+"'")
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func DNSEvidenceDomains(evidence []NativeEvidence) []string {
	domains := make([]string, 0)
	for _, item := range evidence {
		if item.DNSScore > 0 && NormalizeDomain(item.FQDN) != "" {
			domains = append(domains, item.FQDN)
		}
	}
	return normalizedDomains(domains)
}
