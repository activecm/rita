package database

import (
	"context"
	"strconv"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

func (db *DB) createMinMaxMaterializedView() error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
		"rolling":  strconv.FormatBool(db.Rolling),
	})
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.min_max_conn_mv
		TO metadatabase.min_max AS
		SELECT
			{database:String} as database,
			{rolling:Bool} as rolling,
			true as beacon,
			minSimpleState(ts) as min_ts,
			maxSimpleState(ts) as max_ts
		FROM {database:Identifier}.conn c
		GROUP BY (database)
	`); err != nil {
		return err
	}

	// add proxy connections to min_max since their matching conn records get filtered out
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.min_max_http_mv
		TO metadatabase.min_max AS
		SELECT
			{database:String} as database,
			{rolling:Bool} as rolling,
			true as beacon,
			minSimpleState(ts) as min_ts,
			maxSimpleState(ts) as max_ts
		FROM {database:Identifier}.http c
		WHERE method = 'CONNECT'
		GROUP BY (database)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.min_max_openconn_mv
		TO metadatabase.min_max AS
		SELECT
			{database:String} as database,
			{rolling:Bool} as rolling,
			false as beacon,
			minSimpleState(ts) as min_ts,
			maxSimpleState(ts) as max_ts
		FROM {database:Identifier}.openconn c
		GROUP BY (database)
	`); err != nil {
		return err
	}

	// add proxy connections to min_max since their matching conn records get filtered out
	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.min_max_openhttp_mv
		TO metadatabase.min_max AS
		SELECT
			{database:String} as database,
			{rolling:Bool} as rolling,
			false as beacon,
			minSimpleState(ts) as min_ts,
			maxSimpleState(ts) as max_ts
		FROM {database:Identifier}.openhttp c
		WHERE method = 'CONNECT'
		GROUP BY (database)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.min_max_dns_mv
		TO metadatabase.min_max AS
		SELECT
			{database:String} as database,
			{rolling:Bool} as rolling,
			false as beacon,
			minSimpleState(hour) as min_ts,
			maxSimpleState(hour) as max_ts
		FROM {database:Identifier}.udns c
		GROUP BY (database)
	`); err != nil {
		return err
	}

	return nil
}

func (db *DB) createOpenConnTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openconn_tmp (
			import_time DateTime(),
			filtered Bool,
			import_id FixedString(16),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			missing_host_header Bool,
			missing_host_useragent String,
			proto LowCardinality(String),
			service LowCardinality(String),
			conn_state LowCardinality(String),
			duration Float64,
			src_local Bool,
			dst_local Bool,
			icmp_type Int32,
			icmp_code Int32,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			missed_bytes Int64,
			zeek_history String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (filtered, dst_nuid, src_nuid, src, dst, zeek_uid)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createConnTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.conn_tmp (
			import_time DateTime(),
			filtered Bool,
			import_id FixedString(16),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			missing_host_header Bool,
			missing_host_useragent String,
			proto LowCardinality(String),
			service LowCardinality(String),
			conn_state LowCardinality(String),
			duration Float64,
			src_local Bool,
			dst_local Bool,
			icmp_type Int32,
			icmp_code Int32,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			missed_bytes Int64,
			zeek_history String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (filtered, dst_nuid, src_nuid, src, dst, zeek_uid)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createConnTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.conn (
			import_time DateTime(),
			import_id FixedString(16),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			missing_host_header Bool,
			missing_host_useragent String,
			proto LowCardinality(String),
			service LowCardinality(String),
			conn_state LowCardinality(String),
			duration Float64,
			src_local Bool,
			dst_local Bool,
			icmp_type Int32,
			icmp_code Int32,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			missed_bytes Int64,
			zeek_history String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (import_id, missing_host_header, dst_nuid, src_nuid, src, dst, hash)
		ORDER BY (import_id, missing_host_header, dst_nuid, src_nuid, src, dst, hash, ts)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createBigOlHistogramTable(ctx context.Context) error {
	if err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.big_ol_histogram (
			import_hour DateTime(),
			hash FixedString(16),
			bucket DateTime(),
			src_ip_bytes SimpleAggregateFunction(sum, Int64),
			count AggregateFunction(count, UInt64)
		) ENGINE = SummingMergeTree()
		PRIMARY KEY (hash, bucket)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.big_ol_histogram_conn_mv 
		TO {database:Identifier}.big_ol_histogram AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			hash,
			toStartOfFifteenMinutes(ts) as bucket,
			sumSimpleState(src_ip_bytes) as src_ip_bytes,
			countState() as count
		FROM {database:Identifier}.conn
		GROUP BY (import_hour, hash, bucket)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.big_ol_histogram_http_mv 
		TO {database:Identifier}.big_ol_histogram AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			hash,
			toStartOfFifteenMinutes(ts) as bucket,
			sumSimpleState(src_ip_bytes) as src_ip_bytes,
			countState() as count
		FROM {database:Identifier}.http 
		GROUP BY (import_hour, hash, bucket)
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.big_ol_histogram_ssl_mv 
		TO {database:Identifier}.big_ol_histogram AS
		SELECT
			toStartOfHour(import_time) as import_hour,
			hash,
			toStartOfFifteenMinutes(ts) as bucket,
			sumSimpleState(src_ip_bytes) as src_ip_bytes,
			countState() as count
		FROM {database:Identifier}.ssl 
		GROUP BY (import_hour, hash, bucket)
	`); err != nil {
		return err
	}

	return nil
}

func (db *DB) createUconnTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.uconn (
		import_hour DateTime(),
		hour DateTime(),
		hash FixedString(16),
		src IPv6,
		dst IPv6,
		src_nuid UUID,
		dst_nuid UUID,
		src_local Bool,
		dst_local Bool,
		count AggregateFunction(count, Int64),
		unique_ts_count AggregateFunction(uniqExact, DateTime()),
		missing_host_header_count AggregateFunction(count, Int64),
		ts_list AggregateFunction(groupArray(86400), UInt32),
		src_ip_bytes_list AggregateFunction(groupArray(86400), Int64),
		total_src_ip_bytes AggregateFunction(sum, Int64),
		total_dst_ip_bytes AggregateFunction(sum, Int64),
		total_src_bytes AggregateFunction(sum, Int64),
		total_dst_bytes AggregateFunction(sum, Int64),
		total_ip_bytes AggregateFunction(sum, Int64),
		total_src_packets AggregateFunction(sum, Int64),
		total_dst_packets AggregateFunction(sum, Int64),
		total_duration AggregateFunction(sum, Float64),
		first_seen AggregateFunction(min, DateTime()),
		last_seen AggregateFunction(max, DateTime())
	) ENGINE = AggregatingMergeTree()
	ORDER BY (hour, dst_nuid, src_nuid, src, dst, hash)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.uconn_mv 
	TO {database:Identifier}.uconn AS
	SELECT
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		src,
		dst,
		src_nuid,
		dst_nuid,
		hash,
		src_local,
		dst_local,
		countStateIf(missing_host_header = false) as count, -- count only regular conn entries to avoid inflating the count
		uniqExactState(ts) as unique_ts_count,
		countStateIf(missing_host_header = true) as missing_host_header_count,
		groupArrayStateIf(86400)(toUnixTimestamp(ts), missing_host_header = false) as ts_list,
		groupArrayStateIf(86400)(c.src_ip_bytes, missing_host_header = false) as src_ip_bytes_list,
		sumStateIf(c.src_ip_bytes, missing_host_header = false) as total_src_ip_bytes,
		sumStateIf(c.dst_ip_bytes, missing_host_header = false) as total_dst_ip_bytes,
		sumStateIf(c.src_bytes, missing_host_header = false) as total_src_bytes,
		sumStateIf(c.dst_bytes, missing_host_header = false) as total_dst_bytes,
		sumStateIf(c.src_ip_bytes + c.dst_ip_bytes, missing_host_header = false) as total_ip_bytes,
		sumStateIf(c.src_packets, missing_host_header = false) as total_src_packets,
		sumStateIf(c.dst_packets, missing_host_header = false) as total_dst_packets,
		sumStateIf(duration, missing_host_header = false) as total_duration,
		minState(ts) as first_seen,
		maxState(ts) as last_seen
	FROM {database:Identifier}.conn c
	GROUP BY (import_hour, hour, src, src_nuid, dst, dst_nuid, hash, src_local, dst_local)
	`)
	if err != nil {
		return err
	}

	// if db.rolling {
	// 	query += "TTL"
	// }
	return nil
}

func (db *DB) createUconnTmpImportTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.uconn_tmp (
		hash FixedString(16),
		zeek_uid FixedString(16),
		count AggregateFunction(count, UInt64)
	) ENGINE = SummingMergeTree()
	ORDER BY (hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.uconn_tmp_mv 
	TO {database:Identifier}.uconn_tmp AS
	SELECT
		hash AS hash,
		zeek_uid,
		countState() as count
	FROM {database:Identifier}.conn
	GROUP BY (hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createOpenConnHashTmpImportTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.openconnhash_tmp (
		hash FixedString(16),
		zeek_uid FixedString(16),
		count AggregateFunction(count, UInt64)
	) ENGINE = SummingMergeTree()
	ORDER BY (hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.openconnhash_tmp_mv 
	TO {database:Identifier}.openconnhash_tmp AS
	SELECT
		hash AS hash,
		zeek_uid,
		countState() as count
	FROM {database:Identifier}.openconn
	GROUP BY (hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createOpenSNIConnTmpImportTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.opensniconn_tmp (
		conn_type LowCardinality(String),
		hash FixedString(16),
		zeek_uid FixedString(16),
		count AggregateFunction(count, UInt64)
	) ENGINE = MergeTree()
	ORDER BY (conn_type, hash)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.opensniconn_ssl_tmp_mv 
	TO {database:Identifier}.opensniconn_tmp AS
	SELECT
		'ssl' as conn_type,
		hash AS hash,
		zeek_uid,
		countState() as count
	FROM {database:Identifier}.openssl
	GROUP BY (conn_type, hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.opensniconn_http_tmp_mv 
	TO {database:Identifier}.opensniconn_tmp AS
	SELECT
		'http' AS conn_type,
		hash AS hash,
		countState() as count,
		zeek_uid,
	FROM {database:Identifier}.openhttp
	GROUP BY (conn_type, hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createOpenConnTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openconn (
			import_time DateTime(),
			import_id FixedString(16),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			missing_host_header Bool,
			missing_host_useragent String,
			proto LowCardinality(String),
			service LowCardinality(String),
			conn_state LowCardinality(String),
			duration Float64,
			src_local Bool,
			dst_local Bool,
			icmp_type Int32,
			icmp_code Int32,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			missed_bytes Int64,
			zeek_history String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (missing_host_header, dst_nuid, src_nuid, src, dst, hash, zeek_uid)
		ORDER BY (missing_host_header, dst_nuid, src_nuid, src, dst, hash, zeek_uid, ts)
	`)

	return err
}

func (db *DB) createHTTPTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.http_tmp (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			multi_request Bool,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			trans_depth UInt16,
			method LowCardinality(String),
			host String,
			uri String,
			referrer String,
			http_version String,
			useragent String,
			origin String,
			status_code Int64,
			status_msg String,
			info_code Int64,
			info_msg String,
			username String,
			password String,
			src_fuids Array(String),
			src_file_names Array(String),
			src_mime_types Array(String),
			dst_fuids Array(String),
			dst_file_names Array(String),
			dst_mime_types Array(String)
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, host, dst, zeek_uid )
	`)

	return err
}

func (db *DB) createOpenHTTPTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openhttp_tmp (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			multi_request Bool,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			trans_depth UInt16,
			method LowCardinality(String),
			host String,
			uri String,
			referrer String,
			http_version String,
			useragent String,
			origin String,
			status_code Int64,
			status_msg String,
			info_code Int64,
			info_msg String,
			username String,
			password String,
			src_fuids Array(String),
			src_file_names Array(String),
			src_mime_types Array(String),
			dst_fuids Array(String),
			dst_file_names Array(String),
			dst_mime_types Array(String)
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, host, dst, zeek_uid )
	`)

	return err
}

func (db *DB) createHTTPTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.http (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			multi_request Bool,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			trans_depth UInt16,
			method LowCardinality(String),
			host String,
			uri String,
			referrer String,
			http_version String,
			useragent String,
			origin String,
			status_code Int64,
			status_msg String,
			info_code Int64,
			info_msg String,
			username String,
			password String,
			src_fuids Array(String),
			src_file_names Array(String),
			src_mime_types Array(String),
			dst_fuids Array(String),
			dst_file_names Array(String),
			dst_mime_types Array(String)
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, host, dst, hash)
		ORDER BY (dst_nuid, src_nuid, src, host, dst, hash, ts)
	`)

	return err
}

func (db *DB) createOpenHTTPTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openhttp (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			dst_bytes Int64,
			src_ip_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			multi_request Bool,
			trans_depth UInt16,
			method LowCardinality(String),
			host String,
			uri String,
			referrer String,
			http_version String,
			useragent String,
			origin String,
			status_code Int64,
			status_msg String,
			info_code Int64,
			info_msg String,
			username String,
			password String,
			src_fuids Array(String),
			src_file_names Array(String),
			src_mime_types Array(String),
			dst_fuids Array(String),
			dst_file_names Array(String),
			dst_mime_types Array(String)
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, host, dst, hash, zeek_uid)
		ORDER BY (dst_nuid, src_nuid, src, host, dst, hash, zeek_uid, ts)
	`)

	return err
}

func (db *DB) createSSLTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.ssl_tmp (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			src_ip_bytes Int64,
			dst_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			version LowCardinality(String),
			cipher String,
			curve LowCardinality(String),
			server_name String,
			resumed Bool,
			next_protocol LowCardinality(String),
			established Bool,
			server_cert_fuids Array(String),
			client_cert_fuids Array(String),
			server_subject String,
			server_issuer String,
			client_subject String,
			client_issuer String,
			validation_status LowCardinality(String),
			ja3 String,
			ja3s String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, server_name, dst, zeek_uid)
	`)

	return err
}

func (db *DB) createOpenSSLTmpTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openssl_tmp (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			src_ip_bytes Int64,
			dst_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			version LowCardinality(String),
			cipher String,
			curve LowCardinality(String),
			server_name String,
			resumed Bool,
			next_protocol LowCardinality(String),
			established Bool,
			server_cert_fuids Array(String),
			client_cert_fuids Array(String),
			server_subject String,
			server_issuer String,
			client_subject String,
			client_issuer String,
			validation_status LowCardinality(String),
			ja3 String,
			ja3s String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, server_name, dst, zeek_uid)
	`)

	return err
}

func (db *DB) createSSLTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.ssl (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			src_ip_bytes Int64,
			dst_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			version LowCardinality(String),
			cipher String,
			curve LowCardinality(String),
			server_name String,
			resumed Bool,
			next_protocol LowCardinality(String),
			established Bool,
			server_cert_fuids Array(String),
			client_cert_fuids Array(String),
			server_subject String,
			server_issuer String,
			client_subject String,
			client_issuer String,
			validation_status LowCardinality(String),
			ja3 String,
			ja3s String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, server_name, dst, hash)
		ORDER BY (dst_nuid, src_nuid, src, server_name, dst, hash, ts)
	`)

	return err
}

// protocol analysis for ssl connection pair
func (db *DB) createTLSProtoTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.tls_proto (
		import_hour DateTime(),
		hour DateTime(),
		hash FixedString(16),
		ja3 String,
		version String,
		validation_status String,
		count AggregateFunction(count, UInt64)
	) ENGINE = AggregatingMergeTree()
	ORDER BY (hour, hash, ja3, version, validation_status);
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.tls_proto_mv
	TO {database:Identifier}.tls_proto AS
	SELECT
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		hash,
		ja3,
		version,
		validation_status,
		countState() as count
	FROM {database:Identifier}.ssl s
	GROUP BY (import_hour, hour, hash, ja3, ja3s, version, validation_status);
	`)
	if err != nil {
		return err
	}

	return nil
}

// protocol table for http connection pair
func (db *DB) createHTTPProtoTable(ctx context.Context) error {
	if err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.http_proto (
		import_hour DateTime(),
		hour DateTime(),
		hash FixedString(16),
		useragent String,
		method LowCardinality(String),
		referrer String,
		uri String,
		dst_mime_types AggregateFunction(groupUniqArray, String),
		count AggregateFunction(count, UInt64)
	) ENGINE = AggregatingMergeTree()
	ORDER BY (hour, hash, useragent, method, uri);
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.http_proto_mv
		TO {database:Identifier}.http_proto AS
		SELECT
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		hash,
		useragent,
		method,
		referrer,
		uri,
		groupUniqArrayArrayState(h.dst_mime_types) as dst_mime_types,
		countState() as count
		FROM {database:Identifier}.http h
		GROUP BY (import_hour, hour, hash, useragent, method, referrer, uri);
	`); err != nil {
		return err
	}

	return nil
}

func (db *DB) createUSNIConnTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.usni (
		import_hour DateTime(),
		hour DateTime(),
		hash FixedString(16),
		src IPv6,
		dst IPv6,
		src_nuid UUID,
		dst_nuid UUID,
		fqdn String,
		http Bool,
		proxy Bool,
		src_local Bool,
		dst_local Bool,
		count AggregateFunction(count, UInt64),
		proxy_count AggregateFunction(count, UInt64),
		unique_ts_count AggregateFunction(uniqExact, DateTime()),
		ts_list AggregateFunction(groupArray(86400), UInt32),
		src_ip_bytes_list AggregateFunction(groupArray(86400), Int64),
		total_src_ip_bytes AggregateFunction(sum, Int64),
		total_dst_ip_bytes AggregateFunction(sum, Int64),
		total_src_bytes AggregateFunction(sum, Int64),
		total_dst_bytes AggregateFunction(sum, Int64),
		total_ip_bytes AggregateFunction(sum, Int64),
		total_src_packets AggregateFunction(sum, Int64),
		total_dst_packets AggregateFunction(sum, Int64),
		total_duration AggregateFunction(sum, Float64),
		server_ips AggregateFunction(groupUniqArray(10), IPv6),
		proxy_ips AggregateFunction(groupUniqArray(10), IPv6),
		first_seen AggregateFunction(min, DateTime()),
    	last_seen AggregateFunction(max, DateTime())
	)
	ENGINE = AggregatingMergeTree()
	ORDER BY (hour, http, src, src_nuid, src_local, fqdn, hash)
	`)
	if err != nil {
		return err
	}
	err = db.Conn.Exec(ctx, `
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.usni_ssl_mv
	TO {database:Identifier}.usni AS
	SELECT
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		hash,
		src,
		dst,
		src_nuid,
		dst_nuid,
		server_name as fqdn,
		src_local,
		dst_local,
		false as http,
		false as proxy,
		countState() as count,
		uniqExactState(ts) as unique_ts_count,
		groupArrayState(86400)(toUnixTimestamp(ts)) as ts_list,
		groupArrayState(86400)(s.src_ip_bytes) as src_ip_bytes_list,
		sumState(s.src_ip_bytes) as total_src_ip_bytes,
		sumState(s.dst_ip_bytes) as total_dst_ip_bytes,
		sumState(s.src_bytes) as total_src_bytes,
		sumState(s.dst_bytes) as total_dst_bytes,
		sumState(s.src_ip_bytes + s.dst_ip_bytes) as total_ip_bytes,
		sumState(s.src_packets) as total_src_packets,
		sumState(s.dst_packets) as total_dst_packets,
		sumState(duration) as total_duration,
		groupUniqArrayState(10)(dst) as server_ips,
		minState(ts) as first_seen,
		maxState(ts) as last_seen
	FROM {database:Identifier}.ssl s
	GROUP BY (import_hour, hour, src, src_nuid, src_local, dst_local, dst, dst_nuid, fqdn, hash);
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.usni_http_mv
	TO {database:Identifier}.usni AS
	SELECT
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		hash,
		src,
		dst,
		src_nuid,
		dst_nuid,
		host as fqdn,
		src_local,
		dst_local,
		true as http,
		if(method = 'CONNECT', true, false) as proxy,
		countState() as count,
		countStateIf(proxy = true) AS proxy_count,
		uniqExactState(ts) as unique_ts_count,
		groupArrayState(86400)(toUnixTimestamp(ts)) as ts_list,
		groupArrayState(86400)(h.src_ip_bytes) as src_ip_bytes_list,
		sumState(h.src_ip_bytes) as total_src_ip_bytes,
		sumState(h.dst_ip_bytes) as total_dst_ip_bytes,
		sumState(h.src_bytes) as total_src_bytes,
		sumState(h.dst_bytes) as total_dst_bytes,
		sumState(h.src_ip_bytes + h.dst_ip_bytes) as total_ip_bytes,
		sumState(h.src_packets) as total_src_packets,
		sumState(h.dst_packets) as total_dst_packets,
		sumState(duration) as total_duration,
		groupUniqArrayStateIf(10)(dst, method != 'CONNECT') as server_ips,
		groupUniqArrayStateIf(10)(dst, method = 'CONNECT') as proxy_ips,
		minState(ts) as first_seen,
		maxState(ts) as last_seen
	FROM {database:Identifier}.http h
	WHERE h.multi_request == false AND length(h.host) > 0
	GROUP BY (import_hour, hour, src, src_nuid, src_local, dst_local, dst, dst_nuid, fqdn, hash, proxy);
	`)

	return err
}

func (db *DB) createOpenSSLTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.openssl (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			duration Float64,
			src_local Bool,
			dst_local Bool,
			src_bytes Int64,
			src_ip_bytes Int64,
			dst_bytes Int64,
			dst_ip_bytes Int64,
			src_packets Int64,
			dst_packets Int64,
			conn_state LowCardinality(String),
			proto LowCardinality(String),
			service LowCardinality(String),
			version LowCardinality(String),
			cipher String,
			curve LowCardinality(String),
			server_name String,
			resumed Bool,
			next_protocol LowCardinality(String),
			established Bool,
			server_cert_fuids Array(String),
			client_cert_fuids Array(String),
			server_subject String,
			server_issuer String,
			client_subject String,
			client_issuer String,
			validation_status LowCardinality(String),
			ja3 String,
			ja3s String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, server_name, dst, hash, zeek_uid)
		ORDER BY (dst_nuid, src_nuid, src, server_name, dst, hash, zeek_uid, ts)
	`)

	return err
}

func (db *DB) createSNIConnTmpImportTable(ctx context.Context) error {

	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.sniconn_tmp (
		conn_type LowCardinality(String),
		hash FixedString(16),
		zeek_uid FixedString(16),
		count AggregateFunction(count, UInt64)
		-- uids AggregateFunction(groupUniqArray, FixedString(16))
	) ENGINE = MergeTree()
	ORDER BY (conn_type, hash)
	`)

	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.sniconn_ssl_tmp_mv 
	TO {database:Identifier}.sniconn_tmp AS
	SELECT
		'ssl' as conn_type,
		hash AS hash,
		zeek_uid,
		countState() as count
	FROM {database:Identifier}.ssl
	GROUP BY (conn_type, hash, zeek_uid)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.sniconn_http_tmp_mv 
	TO {database:Identifier}.sniconn_tmp AS
	SELECT
		'http' AS conn_type,
		hash AS hash,
		countState() as count,
		zeek_uid,
	FROM {database:Identifier}.http
	GROUP BY (conn_type, hash, zeek_uid)
	`)

	if err != nil {
		return err
	}

	return err
}

func (db *DB) createDNSTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.dns (
			import_time DateTime(),
			zeek_uid FixedString(16),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			src_local Bool,
			dst_local Bool,
			transaction_id UInt16,
			round_trip_time Float64,
			query String,
			query_class_code UInt16,
			query_class_name LowCardinality(String),
			query_type_code UInt16,
			query_type_name LowCardinality(String),
			response_code UInt16,
			response_code_name LowCardinality(String),
			authoritative_answer Bool,
			recursion_desired Bool,
			recursion_available Bool,
			z UInt8,
			answers Array(String),
			ttls Array(UInt32),
			rejected Bool
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, query, dst, hash)
		ORDER BY (dst_nuid, src_nuid, src, query, dst, hash, ts)
	`)

	return err
}

func (db *DB) createUDNSTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.udns (
			import_hour DateTime(),
			hour DateTime(),
			hash FixedString(16),
			tld String,
			fqdn String,
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port  UInt16,
			src_local Bool,
			dst_local Bool,
			visits AggregateFunction(count, UInt64),
			first_seen AggregateFunction(min, DateTime()),
			last_seen AggregateFunction(max, DateTime())
		)
		ENGINE = MergeTree()
		PRIMARY KEY (hour, dst_nuid, src_nuid, src, fqdn, dst, hash)
		ORDER BY (hour, dst_nuid, src_nuid, src, fqdn, dst, hash)
	`)

	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.udns_mv 
	TO {database:Identifier}.udns AS
	SELECT 
		toStartOfHour(import_time) as import_hour,
		toStartOfHour(ts) as hour,
		hash,
		cutToFirstSignificantSubdomain(query) as tld,
		query as fqdn,
		src,
		dst,
		src_nuid,
		dst_nuid,
		src_port,
		dst_port,
		src_local,
		dst_local,
		countState() as visits,
		minState(ts) as first_seen,
		maxState(ts) as last_seen
	FROM {database:Identifier}.dns
	GROUP BY (import_hour, hour, tld, fqdn, src, src_nuid, src_port, dst_port, src_local, dst_local, dst, dst_nuid, hash)
	`)

	return err

}

func (db *DB) createPDNSRawTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.pdns_raw (
			import_time DateTime(),
			hash FixedString(16),
			ts DateTime(),
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_port UInt16,
			dst_port UInt16,
			src_local Bool,
			dst_local Bool,
			transaction_id UInt16,
			round_trip_time Float64,
			query String,
			query_class_code UInt16,
			query_class_name LowCardinality(String),
			query_type_code UInt16,
			query_type_name LowCardinality(String),
			response_code UInt16,
			response_code_name LowCardinality(String),
			authoritative_answer Bool,
			recursion_desired Bool,
			recursion_available Bool,
			z UInt8,
			resolved_ip IPv6,
			ttls Array(UInt32),
		)
		ENGINE = MergeTree()
		PRIMARY KEY (dst_nuid, src_nuid, src, query, dst, hash)
		ORDER BY (dst_nuid, src_nuid, src, query, dst, hash, ts)
	`)

	return err
}

func (db *DB) createPDNSTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
		CREATE TABLE IF NOT EXISTS {database:Identifier}.pdns (
			import_day DateTime(),
			hash FixedString(16),
			day DateTime(),
			tld String,	
			src IPv6,
			dst IPv6,
			src_nuid UUID,
			dst_nuid UUID,
			src_local Bool,
			dst_local Bool,
			fqdn String,
			resolved_ip IPv6,
			first_seen AggregateFunction(min, DateTime()),
			last_seen AggregateFunction(max, DateTime())
		)
		ENGINE = MergeTree()
		PRIMARY KEY (day, tld, dst_nuid, src_nuid, src, fqdn, dst, hash)
	`)

	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.pdns_mv 
	TO {database:Identifier}.pdns AS
	SELECT 
		toStartOfDay(import_time) as import_day,
		toStartOfDay(ts) as day,
		cutToFirstSignificantSubdomain(query) as tld,
		query as fqdn,
		resolved_ip,
		src,
		src_nuid,
		dst,
		dst_nuid,
		hash,
		minState(ts) as first_seen,
		maxState(ts) as last_seen
	FROM {database:Identifier}.pdns_raw
	GROUP BY (import_day, day, tld, fqdn, resolved_ip, src, src_nuid, dst, dst_nuid, hash)
	`)

	return err

}

func (db *DB) createExplodedDNSTable(ctx context.Context) error {
	err := db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.exploded_dns (
		import_hour DateTime(),
		hour DateTime(),
		tld String,
		fqdn String,
		subdomains AggregateFunction(uniqExact, String),
		visits AggregateFunction(count, UInt64)
	) ENGINE = AggregatingMergeTree()
	PRIMARY KEY (hour, tld, fqdn) 
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.exploded_dns_mv
		TO {database:Identifier}.exploded_dns AS
		SELECT
			import_hour,
			hour,
			tld,
			uniqExactState(p.fqdn) as subdomains,
			countMergeState(visits) as visits, -- stores the intermediate state of the visits from the udns AggregateFunction
			t.exploded_dns as fqdn
		FROM (SELECT import_hour, hour, fqdn, tld, visits FROM {database:Identifier}.udns) as p
	    LEFT JOIN (
			-- join the different parts of the array with dots and reverse it again so that it's not backwards
			SELECT DISTINCT fqdn, reverse(arrayStringConcat(exploded, '.')) as exploded_dns FROM (
				-- for each part of the fqdn, create a new array of parts of the fqdn starting from the number of levels in the TLD until the end
				SELECT fqdn, arrayJoin(arrayMap(i -> arraySlice(d, 1, i+(tld_levels)), range(length(d)))) as exploded FROM (
					-- reverse fqdn and split on dots, get number of parts of the TLD
					SELECT fqdn, splitByChar('.', reverse(fqdn)) as d, length(splitByChar('.', tld)) as tld_levels FROM (
						-- grab each unique fqdn
						SELECT DISTINCT fqdn, tld FROM {database:Identifier}.udns
						WHERE tld != '' AND NOT endsWith(tld, '.arpa') AND NOT endsWith(tld, '.local')
					)
				)
			)
		) as t
		ON p.fqdn = t.fqdn
		WHERE tld != '' AND NOT endsWith(tld, '.arpa') AND NOT endsWith(tld, '.local')
		GROUP BY (import_hour, hour, t.exploded_dns, tld)
	`)

	if err != nil {
		return err
	}

	// create temp table
	err = db.Conn.Exec(ctx, `--sql
	CREATE TABLE IF NOT EXISTS {database:Identifier}.dns_tmp (
		tld String,
		count AggregateFunction(count, UInt64)
	) ENGINE = AggregatingMergeTree()
	PRIMARY KEY (tld)
	`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
	CREATE MATERIALIZED VIEW IF NOT EXISTS {database:Identifier}.dns_tmp_mv 
	TO {database:Identifier}.dns_tmp AS
	SELECT
		cutToFirstSignificantSubdomain(query) AS tld,
		countState() as count
	FROM {database:Identifier}.dns
	GROUP BY (tld)
	`)

	if err != nil {
		return err
	}

	return err
}

func (db *DB) createSensorDBTables() error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	if err := db.createConnTmpTable(ctx); err != nil {
		return err
	}
	if err := db.createSSLTmpTable(ctx); err != nil {
		return err
	}
	if err := db.createHTTPTmpTable(ctx); err != nil {
		return err
	}
	if err := db.createOpenConnTmpTable(ctx); err != nil {
		return err
	}
	if err := db.createOpenSSLTmpTable(ctx); err != nil {
		return err
	}
	if err := db.createOpenHTTPTmpTable(ctx); err != nil {
		return err
	}

	if err := db.createConnTable(ctx); err != nil {
		return err
	}

	if err := db.createUconnTable(ctx); err != nil {
		return err
	}

	err := db.createUconnTmpImportTable(ctx)
	if err != nil {
		return err
	}

	err = db.createOpenConnTable(ctx)
	if err != nil {
		return err
	}

	err = db.createHTTPTable(ctx)
	if err != nil {
		return err
	}

	err = db.createOpenHTTPTable(ctx)
	if err != nil {
		return err
	}

	err = db.createSSLTable(ctx)
	if err != nil {
		return err
	}

	err = db.createOpenSSLTable(ctx)
	if err != nil {
		return err
	}

	err = db.createUSNIConnTable(ctx)
	if err != nil {
		return err
	}

	err = db.createTLSProtoTable(ctx)
	if err != nil {
		return err
	}

	err = db.createHTTPProtoTable(ctx)
	if err != nil {
		return err
	}

	err = db.createSNIConnTmpImportTable(ctx)
	if err != nil {
		return err
	}

	err = db.createOpenConnHashTmpImportTable(ctx)
	if err != nil {
		return err
	}

	err = db.createOpenSNIConnTmpImportTable(ctx)
	if err != nil {
		return err
	}

	err = db.createBigOlHistogramTable(ctx)
	if err != nil {
		return err
	}

	err = db.createDNSTable(ctx)
	if err != nil {
		return err
	}

	err = db.createUDNSTable(ctx)
	if err != nil {
		return err
	}

	err = db.createPDNSRawTable(ctx)
	if err != nil {
		return err
	}

	err = db.createPDNSTable(ctx)
	if err != nil {
		return err
	}

	err = db.createExplodedDNSTable(ctx)
	if err != nil {
		return err
	}

	if err := db.createMinMaxMaterializedView(); err != nil {
		return err
	}

	return err
}

func (server *ServerConn) CreateServerDBTables() error {
	err := server.createMetaDatabase()
	if err != nil {
		return err
	}

	return nil
}
