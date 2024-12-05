package database

import (
	"context"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

func (db *DB) createThreatMixtapeTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.threat_mixtape (
			analyzed_at DateTime64(6),
			import_id FixedString(16),
			hash FixedString(16),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			fqdn String,
			server_ips Array(IPv6),
			proxy_ips Array(IPv6),
			total_bytes UInt64,
			last_seen DateTime(),
			port_proto_service Array(String),

			-- counts
			count UInt64,
			ts_unique UInt64,
			proxy_count UInt64,
			open_count UInt64,

			-- c2 over dns connection info
			direct_conns Array(IPv6),
			queried_by Array(IPv6),

			-- **** THREAT INDICATORS ****
			-- BEACONING
			beacon_type LowCardinality(String),
			beacon_score Float32,
			beacon_threat_score Float32,
			ts_score Float32,
			ds_score Float32,
			dur_score Float32,
			hist_score Float32,
			ts_intervals Array(Int64),
			ts_interval_counts Array(Int64),
			ds_sizes Array(Int64),
			ds_size_counts Array(Int64),
			
			-- LONG CONNECTIONS
			total_duration Float64,
			long_conn_score Float32,

			-- STROBE
			strobe_score Float32,

			-- C2 OVER DNS
			subdomain_count UInt64,
			c2_over_dns_score Float32,
			c2_over_dns_direct_conn_score Float32,

			-- THREAT INTEL
			threat_intel Bool,
			threat_intel_score Float32,

			-- **** MODIFIERS ****
			modifier_name LowCardinality(String),
			modifier_score Float32,
			modifier_value String,

			-- PREVALENCE
			prevalence_total UInt64,
			prevalence Float32,
			prevalence_score Float32,

			first_seen_historical DateTime(),
			first_seen_score Float32,

			-- THREAT INTEL DATA SIZE
			threat_intel_data_size_score Float32,


			-- MISSING HOST HEADER
			missing_host_count UInt64,
			missing_host_header_score Float32

		) ENGINE = MergeTree()
		PRIMARY KEY (analyzed_at, dst_nuid, src_nuid, src, fqdn, dst, hash)
		ORDER BY (analyzed_at, dst_nuid, src_nuid, src, fqdn, dst, hash)
	`)
	return err
}

func (db *DB) createHistoricalFirstSeenMaterializedViews(ctx context.Context) error {
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_conn_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				if(src_local = true, dst, src) as ip,
				'' as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.conn
		GROUP BY (fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_openconn_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				if(src_local = true, dst, src) as ip,
				'' as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.openconn
		GROUP BY (fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_ssl_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				'::' as ip,
				server_name as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.ssl
		GROUP BY ( fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_openssl_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				'::' as ip,
				server_name as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.openssl
		GROUP BY ( fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_http_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				'::' as ip,
				host as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.http
		GROUP BY ( fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_openhttp_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				'::' as ip,
				host as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.openhttp
		GROUP BY ( fqdn, ip)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.historical_first_seen_dns_mv
		TO metadatabase.historical_first_seen AS
			SELECT
				'::' as ip,
				query as fqdn,
				minSimpleState(ts) as first_seen,
				maxSimpleState(ts) as last_seen
		FROM {database:Identifier}.dns
		GROUP BY ( fqdn, ip)
	`); err != nil {
		return err
	}

	return nil
}

func (db *DB) createMIMETypeURIsTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.mime_type_uris (
			import_hour DateTime(),
			hour DateTime(),
			hash FixedString(16),
			uri String,
			path String,
			extension String,
			mime_type String,
			mismatch_count AggregateFunction(count, UInt64),
		)
		ENGINE = AggregatingMergeTree()
		PRIMARY KEY (hour, hash, uri)
	`)

	if err != nil {
		return err
	}
	// This view is used to detect MIME type/URI mismatches
	// If a HTTP connection's MIME type matches a MIME type in the metadatabase.valid_mime_types table
	// and its extension does not match the associated values for that MIME type, then it should be added to this table
	err = db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.mime_type_uris_mv
		TO {database:Identifier}.mime_type_uris AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			hash,
			uri,
			path(uri) as path,
			-- get the extension from the path
			CASE
				-- if the path does not contain a . or ends with a ., then the extension is an empty string
				WHEN position(reverse(arrayElement(splitByChar('/', path), -1)), '.') = 0 OR endsWith(path, '.') THEN ''
				-- otherwise, split the last segment by . and take the last element as the extension
				ELSE splitByChar('.', arrayElement(splitByChar('/', path), -1))[-1]
			END AS extension,
			dst_mime_types as mime_type,
			countState() AS mismatch_count
		FROM {database:Identifier}.http h
		-- for each uri, get the extension and join it with the valid mime types, 
		-- keeping only the rows where the extension does not match the valid extension
	    ARRAY JOIN dst_mime_types
		LEFT SEMI JOIN metadatabase.valid_mime_types v ON dst_mime_types = v.mime_type
		WHERE uri != '/' AND extension != v.extension
		GROUP BY import_hour, hour, hash, uri, path, extension, mime_type
	`)

	if err != nil {
		return err
	}
	return nil
}

func (db *DB) createRareSignatureTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.rare_signatures (
			import_hour DateTime(),
			hour DateTime(),
			src IPv6,
			src_nuid UUID,
			dst IPv6,
			dst_nuid UUID,
			fqdn String,
			signature String,
			is_ja3 Bool,
			times_used_dst AggregateFunction(uniqExact, IPv6),
			times_used_fqdn AggregateFunction(uniqExact, String)
		)
		ENGINE = AggregatingMergeTree()
		PRIMARY KEY (hour, src_nuid, src, dst, dst_nuid, fqdn, signature )
	`)

	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.rare_signatures_http_mv
		TO {database:Identifier}.rare_signatures AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			src,
			src_nuid,
			host AS fqdn,
			useragent as signature,
			false as is_ja3,
			uniqExactState(dst) as times_used_dst,
			uniqExactState(host) as times_used_fqdn
		FROM {database:Identifier}.http
		WHERE length(useragent) > 0 AND length(host) > 0
		GROUP BY (import_hour, hour, src, src_nuid, fqdn, signature, is_ja3)
	`)

	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.rare_signatures_ssl_mv
		TO {database:Identifier}.rare_signatures AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			src,
			src_nuid,
			server_name AS fqdn,
			ja3 as signature,
			true as is_ja3,
			uniqExactState(dst) as times_used_dst,
			uniqExactState(server_name) as times_used_fqdn
		FROM {database:Identifier}.ssl
		WHERE length(ja3) > 0
		GROUP BY (import_hour, hour, src, src_nuid, fqdn, signature, is_ja3)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.rare_signatures_missing_host_mv
		TO {database:Identifier}.rare_signatures AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			src,
			src_nuid,
			dst,
			dst_nuid,
			missing_host_useragent as signature,
			false as is_ja3,
			uniqExactState(if(src_local, dst, src)) as times_used_dst
		FROM {database:Identifier}.conn
		WHERE length(missing_host_useragent) > 0 AND missing_host_header = true
		GROUP BY (import_hour, hour, src, src_nuid, dst, dst_nuid, signature, is_ja3)
	`)
	if err != nil {
		return err
	}

	return err

}
func (db *DB) createPortInfoTable(ctx context.Context) error {

	if err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.port_info (
			import_hour DateTime(),
			hour DateTime(),
			hash FixedString(16),
			src IPv6,
			src_nuid UUID,
			dst IPv6,
			dst_nuid UUID,
			fqdn String,
			dst_port UInt16,
			proto LowCardinality(String),
			service LowCardinality(String),
			icmp_type UInt16,
			icmp_code UInt16,
			conn_state LowCardinality(String),
			count AggregateFunction(count, UInt64),
			bytes_sent AggregateFunction(sum, Int64),
			bytes_received AggregateFunction(sum, Int64)
		)
		ENGINE = AggregatingMergeTree()
		PRIMARY KEY (hour, hash, dst_port, proto, service, conn_state, icmp_type, icmp_code)
	`); err != nil {
		return err
	}

	// conn
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.port_info_ip_mv
		TO {database:Identifier}.port_info AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			hash,
			src,
			src_nuid,
			dst,
			dst_nuid,
			dst_port,
			proto,
			service,
			if(proto = 'icmp', src_port, 0) as icmp_type,
			if(proto = 'icmp', dst_port, 0) as icmp_code,
			conn_state,
			countState() as count,
			sumState(src_ip_bytes) as bytes_sent,
			sumState(dst_ip_bytes) as bytes_received
		FROM {database:Identifier}.conn
		WHERE missing_host_header = false
		GROUP BY (import_hour, hour, hash, src, src_nuid, dst, dst_nuid, dst_port, proto, service, icmp_type, icmp_code, conn_state)
	`); err != nil {
		return err
	}

	// http
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.port_info_http_mv
		TO {database:Identifier}.port_info AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			hash,
			src,
			src_nuid,
			host as fqdn,
			dst_port,
			proto,
			service,
			conn_state,
			countStateIf(multi_request = false) as count, -- only count unique zeek_uids, not each multi-request
			sumState(src_ip_bytes) as bytes_sent,
			sumState(dst_ip_bytes) as bytes_received
		FROM {database:Identifier}.http
		GROUP BY (import_hour, hour, hash, src, src_nuid, fqdn, dst_port, proto, service, conn_state)
	`); err != nil {
		return err
	}

	// ssl
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.port_info_ssl_mv
		TO {database:Identifier}.port_info AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			toStartOfHour(ts) as hour,
			hash,
			src,
			src_nuid,
			server_name as fqdn,
			dst_port,
			proto,
			service,
			conn_state,
			countState() as count,
			sumState(src_ip_bytes) as bytes_sent,
			sumState(dst_ip_bytes) as bytes_received
		FROM {database:Identifier}.ssl
		GROUP BY (import_hour, hour, hash, src, src_nuid, fqdn, dst_port, proto, service, conn_state)
	`); err != nil {
		return err
	}

	return nil
}

func (db *DB) createSensorDBAnalysisTables() error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	err := db.createThreatMixtapeTable(ctx)
	if err != nil {
		return err
	}

	err = db.createRareSignatureTable(ctx)
	if err != nil {
		return err
	}

	err = db.createMIMETypeURIsTable(ctx)
	if err != nil {
		return err
	}

	err = db.createPortInfoTable(ctx)
	if err != nil {
		return err
	}

	// only create historical first seen mvs for rolling datasets
	if db.Rolling {
		err = db.createHistoricalFirstSeenMaterializedViews(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
