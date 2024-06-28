package viewer

import (
	"activecm/rita/config"
	"activecm/rita/database"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type MixtapeResult struct {
	Src                      net.IP    `ch:"src" json:"src"`
	Dst                      net.IP    `ch:"dst" json:"dst"`
	FQDN                     string    `ch:"fqdn"`
	FinalScore               float32   `ch:"final_score"`
	Count                    uint64    `ch:"count"`
	ProxyCount               uint64    `ch:"proxy_count"`
	BeaconScore              float32   `ch:"beacon_score"`
	StrobeScore              float32   `ch:"strobe_score"`
	BeaconThreatScore        float32   `ch:"beacon_threat_score"`
	TotalDuration            float32   `ch:"total_duration"`
	LongConnScore            float32   `ch:"long_conn_score"`
	FirstSeen                time.Time `ch:"first_seen_historical"`
	FirstSeenScore           float32   `ch:"first_seen_score"`
	Prevalence               float32   `ch:"prevalence"`
	PrevalenceScore          float32   `ch:"prevalence_score"`
	Subdomains               uint64    `ch:"subdomains"`
	PortProtoService         []string  `ch:"port_proto_service"`
	C2OverDNSScore           float32   `ch:"c2_over_dns_score"`
	C2OverDNSDirectConnScore float32   `ch:"c2_over_dns_direct_conn_score"`
	ThreatIntelScore         float32   `ch:"threat_intel_score"`
	ThreatIntelDataSizeScore float32   `ch:"threat_intel_data_size_score"`
	TotalBytes               uint64    `ch:"total_bytes"`
	TotalBytesFormatted      string    `ch:"total_bytes_formatted"`
	MissingHostHeaderScore   float32   `ch:"missing_host_header_score"`
	MissingHostCount         uint64    `ch:"missing_host_count"`
	ProxyIPs                 []net.IP  `ch:"proxy_ips"`

	TotalModifierScore float32 `ch:"total_modifier_score"`
}

type Item MixtapeResult

func (i Item) GetSrc() string {
	if i.Src.String() == "::" && i.Dst.String() == "::" && len(i.FQDN) > 0 {
		return ""
	}

	return i.Src.String()
}
func (i Item) GetDst() string {
	if i.Dst.String() == "::" && len(i.FQDN) > 0 {
		return i.FQDN
	}
	return i.Dst.String()
}

// func (i item) FQDN() string           { return i.fqdn }
func (i Item) GetBeacon() string {
	// if connection is a strobe, set beacon score to 100%
	if i.StrobeScore > 0 {
		return renderIndicator(i.StrobeScore, "100%")
	}
	return renderIndicator(i.BeaconThreatScore, fmt.Sprintf("%1.2f%%", i.BeaconScore*100))
}
func (i Item) GetFirstSeen(relativeTimestamp time.Time) string {
	timeAgo := relativeTimestamp.Sub(i.FirstSeen)
	switch {
	case timeAgo.Hours() >= 8760:
		months := int(math.Floor(timeAgo.Hours() / 8760))
		text := "years"
		if months == 1 {
			text = "year"
		}
		return fmt.Sprintf("%d %s ago", months, text)
	case timeAgo.Hours() >= 720:
		months := int(math.Floor(timeAgo.Hours() / 720))
		text := "months"
		if months == 1 {
			text = "month"
		}
		return fmt.Sprintf("%d %s ago", months, text)
	case timeAgo.Hours() >= 24:
		days := int(math.Floor(timeAgo.Hours() / 24))
		text := "days"
		if days == 1 {
			text = "day"
		}
		return fmt.Sprintf("%d %s ago", days, text)
	case timeAgo.Hours() < 1:
		minutes := int(math.Floor(timeAgo.Minutes()))
		text := "minutes"
		if minutes == 1 {
			text = "minute"
		}
		return fmt.Sprintf("%d %s ago", minutes, text)
	}

	text := "hours"
	if math.Floor(timeAgo.Hours()) == 1 {
		text = "hour"
	}
	return fmt.Sprintf("%d %s ago", int(math.Floor(timeAgo.Hours())), text)
}
func (i Item) GetTotalDuration() string {
	return renderIndicator(i.LongConnScore, time.Duration(i.TotalDuration*float32(time.Second)).Truncate(time.Second).String())
}
func (i Item) GetPrevalence() string {
	return renderIndicator(i.PrevalenceScore, fmt.Sprintf("%1.2f%%", i.Prevalence))
}
func (i Item) GetSubdomains() string {
	return renderIndicator(i.C2OverDNSScore, fmt.Sprintf("%d", i.Subdomains))
}

func (i Item) GetPortProtoService() []string { return i.PortProtoService }

func (i Item) GetThreatIntel() string {
	if i.ThreatIntelScore > 0 {
		return "⛔"
	}
	return ""
}

func (i Item) FilterValue() string { return i.GetSrc() } // no-op
func (i Item) GetSeverity(color bool) string {
	caser := cases.Title(language.English)

	var severity config.ImpactCategory
	if i.FinalScore > config.HIGH_CATEGORY_SCORE {
		severity = config.CriticalThreat
		if DebugMode {
			return lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("%1.2f%%", i.FinalScore*100))
		}
		if color {
			return lipgloss.NewStyle().Foreground(red).Render(caser.String(string(severity)))
		}

	} else {
		severity = config.GetImpactCategoryFromScore(i.FinalScore)
		if DebugMode {
			return renderIndicator(i.FinalScore, fmt.Sprintf("%1.2f%%", i.FinalScore*100))
		}
		if color {
			return renderIndicator(i.FinalScore, caser.String(string(severity)))
		}
	}
	return caser.String(string(severity))
}

func GetResults(db *database.DB, filter Filter, currentPage, pageSize int, minTimestamp time.Time) ([]list.Item, bool, error) {
	// build query
	query, params, appliedFilter := BuildResultsQuery(filter, currentPage, pageSize, minTimestamp)

	// set context
	ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(params))

	// query database for results
	rows, err := db.Conn.Query(ctx, query)
	if err != nil {
		return nil, false, err
	}

	var items []list.Item
	for rows.Next() {
		var res Item
		if err := rows.ScanStruct(&res); err != nil {
			return nil, false, fmt.Errorf("could not read mixtape result for viewer: %w", err)
		}
		items = append(items, list.Item(res))
	}

	rows.Close()

	return items, appliedFilter, nil
}

func BuildResultsQuery(filter Filter, currentPage, pageSize int, minTimestamp time.Time) (string, clickhouse.Parameters, bool) {
	params := clickhouse.Parameters{}
	query := `--sql
		SELECT src, dst, fqdn,
		count,
		proxy_count,
		proxy_ips,
		total_bytes,
		total_bytes_formatted,
		subdomains,
		-- arrayDistinct(flatten(port_proto_service)) as port_proto_service,
		port_proto_service,
		beacon_score as beacon_score,
		beacon_threat_score,
		c2_over_dns_score,
		strobe_score,
		total_duration,
		long_conn_score,
		prevalence,
		prevalence_score,
		first_seen_historical,
		first_seen_score,
		threat_intel_score,
		threat_intel_data_size_score,
		missing_host_count,
		missing_host_header_score,
		c2_over_dns_direct_conn_score,
		total_modifier_score,
		toFloat32(base_score + total_modifier_score + prevalence_score + first_seen_score + missing_host_header_score + threat_intel_data_size_score + c2_over_dns_direct_conn_score) as final_score
		-- base_score
		-- total_modifier_score
	
		FROM (
		SELECT hash, src, dst, fqdn,
			groupUniqArrayArray(proxy_ips) as proxy_ips,
			max(proxy_count) as proxy_count,
			max(count) as count,
			sum(total_bytes) as total_bytes,
			formatReadableSize(total_bytes) as total_bytes_formatted,
			sum(subdomain_count) as subdomains,
			flatten(groupArray(port_proto_service)) as port_proto_service,
			toFloat32(sum(beacon_score)) as beacon_score,
			toFloat32(sum(beacon_threat_score)) as beacon_threat_score,
			toFloat32(sum(c2_over_dns_score)) as c2_over_dns_score,
			toFloat32(sum(strobe_score)) as strobe_score,
			toFloat32(sum(total_duration)) as total_duration,
			toFloat32(sum(long_conn_score)) as  long_conn_score,
			toFloat32(sum(prevalence)) as prevalence,
			toFloat32(sum(prevalence_score)) as prevalence_score,
			max(first_seen_historical) as first_seen_historical,
			toFloat32(sum(first_seen_score)) as first_seen_score,
			toFloat32(sum(threat_intel_score)) as threat_intel_score,
			toFloat32(sum(threat_intel_data_size_score)) as threat_intel_data_size_score,
			sum(missing_host_count) as missing_host_count,
			toFloat32(sum(missing_host_header_score)) as missing_host_header_score,
			toFloat32(sum(c2_over_dns_direct_conn_score)) as c2_over_dns_direct_conn_score,
			toFloat32(sum(modifier_score)) as total_modifier_score,
			greatest(beacon_threat_score, long_conn_score, strobe_score, c2_over_dns_score, threat_intel_score) as base_score
		FROM threat_mixtape t
		INNER JOIN (SELECT hash, argMax(import_id, last_seen) as import_id, max(last_seen) as max_last_seen FROM threat_mixtape GROUP BY hash) x
		ON t.hash = x.hash and t.last_seen = x.max_last_seen and t.import_id = x.import_id
		WHERE toStartOfHour(t.last_seen) >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
 `

	// build conditions for query based on filter

	// set where conditions for src and dst filters
	whereConditions := []string{}
	if filter.Src != "" {
		whereConditions = append(whereConditions, "src={src:String}")
		params["src"] = filter.Src
	}
	if filter.Dst != "" {
		whereConditions = append(whereConditions, "dst={dst:String}")
		params["dst"] = filter.Dst
	}
	if filter.Fqdn != "" {
		whereConditions = append(whereConditions, "fqdn={fqdn:String}")
		params["fqdn"] = filter.Fqdn
	}
	if filter.ThreatIntel != "" {
		whereConditions = append(whereConditions, "threat_intel={threat_intel:Bool}")
		params["threat_intel"] = filter.ThreatIntel
	}
	if !filter.LastSeen.IsZero() {
		whereConditions = append(whereConditions, "toStartOfHour(last_seen) >= {last_seen:Int64}")
		params["last_seen"] = fmt.Sprintf("%d", filter.LastSeen.UTC().Unix())
	}

	// set where conditions for src and dst filters to query if any were specified
	if len(whereConditions) > 0 {
		query += "AND " + strings.Join(whereConditions, " AND ")
	}

	// set group by
	query += `--sql
		GROUP BY hash, src, dst, fqdn
 	`

	// set having conditions for numerical filters
	havingConditions := []string{}
	if filter.Count.Value != "" && filter.Count.Operator != "" {
		havingConditions = append(havingConditions, "count "+filter.Count.Operator+" {count:Int64}")
		params["count"] = filter.Count.Value
	}

	if filter.Beacon.Value != "" && filter.Beacon.Operator != "" {
		havingConditions = append(havingConditions, "beacon_score "+filter.Beacon.Operator+" {beacon:Float32}")
		params["beacon"] = filter.Beacon.Value
	}

	if filter.Subdomains.Value != "" && filter.Subdomains.Operator != "" {
		havingConditions = append(havingConditions, "subdomain_count "+filter.Subdomains.Operator+" {subdomains:Int64}")
		params["subdomains"] = filter.Subdomains.Value
	}

	if filter.Duration.Value != "" && filter.Duration.Operator != "" {
		if filter.Duration.Operator == "=" {
			// round column down to the nearest integer if the operator is equ
			havingConditions = append(havingConditions, "floor(total_duration) "+filter.Duration.Operator+" {duration:Float64}")
		} else {
			havingConditions = append(havingConditions, "total_duration "+filter.Duration.Operator+" {duration:Float64}")
		}
		params["duration"] = filter.Duration.Value
	}

	// add having conditions to query if any were specified
	if len(havingConditions) > 0 {
		query += "HAVING " + strings.Join(havingConditions, " AND ")
	}

	// add parentheses to close subquery
	query += `--sql
	)`

	// add where conditions to the outer part of the query if any were specified
	outerWhereConditions := []string{}
	// add conditions for severity filter to query
	if len(filter.Severity) > 0 {
		for i, op := range filter.Severity {
			paramName := fmt.Sprintf("final_score_%d", i)
			outerWhereConditions = append(outerWhereConditions, "final_score "+op.Operator+fmt.Sprintf("{%s:Float32}", paramName))
			params[paramName] = op.Value
		}
		query += "WHERE " + strings.Join(outerWhereConditions, " AND ")
	}

	// set sorting conditions if any were specified
	sortingConditions := []string{}
	if filter.SortSeverity != "" {
		sortingConditions = append(sortingConditions, "final_score "+filter.SortSeverity)
	}
	if filter.SortBeacon != "" {
		sortingConditions = append(sortingConditions, "beacon_score "+filter.SortBeacon)
	}
	if filter.SortDuration != "" {
		sortingConditions = append(sortingConditions, "total_duration "+filter.SortDuration)
	}
	if filter.SortSubdomains != "" {
		sortingConditions = append(sortingConditions, "subdomains "+filter.SortSubdomains)
	}

	// add sorting conditions to query if any were specified
	if len(sortingConditions) > 0 {
		query += "ORDER BY " + strings.Join(sortingConditions, ",")
	} else {
		query += `--sql
			ORDER BY final_score DESC, strobe_score DESC, beacon_score DESC
		`
	}

	offset := currentPage * pageSize
	// set offset ; fetch if the offset is greater than 0, otherwise set limit
	if offset > 0 {
		query += `--sql
			OFFSET {skip:Int32} ROWS FETCH NEXT {page_size:Int32} ROWS ONLY
		 `
		params["skip"] = fmt.Sprintf("%d", offset)
	} else {
		query += `--sql
		LIMIT {page_size:Int32}
		`
	}
	params["page_size"] = fmt.Sprint(pageSize)
	params["min_ts"] = fmt.Sprintf("%d", minTimestamp.UTC().Unix())
	appliedFilter := len(whereConditions) > 0 || len(havingConditions) > 0 || len(outerWhereConditions) > 0 || len(sortingConditions) > 0
	return query, params, appliedFilter
}
