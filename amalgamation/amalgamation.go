package amalgamation

import (
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/activecm/rita/v5/analysis"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"
	"golang.org/x/time/rate"
)

type Amalgamator struct {
	Database    *database.DB
	ImportID    util.FixedString
	Config      *config.Config
	MixtapeChan chan analysis.ThreatMixtape

	writer *database.BulkWriter
}

func NewAmalgamator(db *database.DB, importID *util.FixedString, cfg *config.Config) *Amalgamator {
	limiter := rate.NewLimiter(5, 5)
	return &Amalgamator{
		Database:    db,
		ImportID:    *importID,
		Config:      cfg,
		MixtapeChan: make(chan analysis.ThreatMixtape),
		writer:      database.NewBulkWriter(db, cfg, 1, db.GetSelectedDB(), "final_mixtape", "INSERT INTO {database:Identifier}.final_mixtape", limiter, false),
	}
}

func (a *Amalgamator) Amalgamate() error {
	zlog := logger.GetLogger()
	zlog.Debug().Msg("Starting Amalgamation")

	ctx := a.Database.QueryParameters(clickhouse.Parameters{
		"database":  a.Database.GetSelectedDB(),
		"import_id": a.ImportID.Hex(),
	})

	fmt.Println("Import ID:", a.ImportID.Hex())

	a.writer.Start(0)

	rows, err := a.Database.Conn.Query(ctx, `
		SELECT 
			analyzed_at, import_id, hash, src, src_nuid, dst, dst_nuid, fqdn, beacon_score, beacon_type, long_conn_score, total_duration, strobe_score, count,
			threat_intel, threat_intel_score, threat_intel_data_size_score, total_bytes, c2_over_dns_score, c2_over_dns_direct_conn_score, subdomain_count,
			prevalence, prevalence_score, prevalence_total, network_size, last_seen,
			first_seen_historical, first_seen_score, missing_host_count, missing_host_header_score, 
			-- modifiers, 
			port_proto_service,
			total_modifier_score, beacon_threat_score, ts_score, hist_score, ds_score,
			c2_over_dns_score, long_conn_score, strobe_score, threat_intel_score,
			server_ips, proxy_ips,
			toFloat32(base_score + total_modifier_score + prevalence_score + first_seen_score + missing_host_header_score + threat_intel_data_size_score + c2_over_dns_direct_conn_score) as final_score,
			greatest(beacon_threat_score, long_conn_score, strobe_score, c2_over_dns_score, threat_intel_score) as base_score,
			connection_graph_intervals, connection_graph_counts, data_size_graph_intervals, data_size_graph_counts
		FROM (
			SELECT analyzed_at, import_id, hash, src, src_nuid, dst, dst_nuid, fqdn, 
				groupArrayArray(server_ips) AS server_ips, groupArrayArray(proxy_ips) AS proxy_ips, 
				toFloat32(sum(beacon_score)) AS beacon_score, 
				max(last_seen) AS last_seen,
				max(beacon_type) AS beacon_type,
				toFloat32(sum(long_conn_score)) AS long_conn_score, sum(total_duration) AS total_duration,
				toFloat32(sum(strobe_score)) AS strobe_score, sum(count) AS count, 
				groupArrayArray(ts_intervals) AS connection_graph_intervals,
				groupArrayArray(ts_interval_counts) AS connection_graph_counts,
				groupArrayArray(ds_sizes) AS data_size_graph_intervals,
				groupArrayArray(ds_size_counts) AS data_size_graph_counts,
				max(threat_intel) AS threat_intel, toFloat32(sum(threat_intel_score)) AS threat_intel_score, toFloat32(sum(threat_intel_data_size_score)) AS threat_intel_data_size_score, 
				sum(total_bytes) AS total_bytes,
				toFloat32(sum(c2_over_dns_score)) AS c2_over_dns_score, toFloat32(sum(c2_over_dns_direct_conn_score)) AS c2_over_dns_direct_conn_score, sum(subdomain_count) AS subdomain_count,
				toFloat32(sum(prevalence)) AS prevalence, toFloat32(sum(prevalence_score)) AS prevalence_score, sum(prevalence_total) AS prevalence_total, sum(network_size) AS network_size,
				max(first_seen_historical) as first_seen_historical, toFloat32(sum(first_seen_score)) AS first_seen_score,
				sum(missing_host_count) AS missing_host_count,
				toFloat32(sum(missing_host_header_score)) as missing_host_header_score,
				-- groupUniqArrayIf(map(modifier_name, tuple( modifier_value,  modifier_score) ), modifier_name != '') as modifiers,
				arrayDistinct(flatten(groupUniqArray(port_proto_service))) as port_proto_service,
				toFloat32(sum(modifier_score)) as total_modifier_score,
				toFloat32(sum(ts_score)) as ts_score,
				toFloat32(sum(hist_score)) as hist_score,
				toFloat32(sum(ds_score)) as ds_score,
				toFloat32(sum(beacon_threat_score)) as beacon_threat_score
			FROM {database:Identifier}.threat_mixtape t
			WHERE import_id = unhex({import_id:String})
			GROUP BY analyzed_at, import_id, hash, src, src_nuid, dst, dst_nuid, fqdn
		)
   `)

	if err != nil {
		return err
	}

	for rows.Next() {
		var mixtape analysis.ThreatMixtape
		// fmt.Println(mixtape.Hash.Hex())
		if err := rows.ScanStruct(&mixtape); err != nil {
			return err
		}
		a.writer.WriteChannel <- &mixtape
	}

	a.writer.Close()
	return nil
}
