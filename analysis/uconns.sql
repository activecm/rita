@set min_ts=0
@set rolling=false
@set network_size=10
@set unique_thresh=4

WITH unique_http AS (
			SELECT DISTINCT hash FROM sniconn_tmp
			WHERE conn_type = 'http'
		),
		prevalence_counts AS (
			SELECT ip, count() as prevalence_total FROM (
				SELECT DISTINCT if(src_local, dst, src) as ip, if(src_local, src, dst) as internal FROM uconn
				WHERE hour >= toStartOfHour(fromUnixTimestamp(:min_ts))
				
				UNION DISTINCT 
				
				SELECT DISTINCT if(src_local, dst, src) as ip, if(src_local, src, dst) as internal FROM openconn
			)
			GROUP BY ip
		),  
		sniconns AS ( -- usni connections that will be beacons in this import
			SELECT hash, uniqExactMerge(u.unique_ts_count) AS unique_count, countMerge(u.count) AS total_count
			FROM usni u
			LEFT SEMI JOIN sniconn_tmp t USING hash
			WHERE hour >= toStartOfHour(fromUnixTimestamp(:min_ts))
			GROUP BY hash
			HAVING unique_count >= :unique_thresh AND total_count < 86400

		), uid_list AS ( -- list of unique Zeek UID's used by SNI beacons in this import
			SELECT DISTINCT zeek_uid FROM sniconn_tmp
			INNER JOIN sniconns USING hash
			UNION DISTINCT
			-- open conns don't need to be joined on the potential beacons list bc open conns aren't used in beaconing
			SELECT DISTINCT zeek_uid from opensniconn_tmp
		), filtered_hashes AS ( -- list of unique hashes for uconns that were not used by SNI beacons in this import
			SELECT DISTINCT hash FROM uconn_tmp u
			-- this is used instead of an anti join because we need to query hashes that aren't associated with any zeek_uids from SNI
			LEFT JOIN uid_list ui ON u.zeek_uid = ui.zeek_uid
			GROUP BY hash
			HAVING countIf(u.zeek_uid = ui.zeek_uid) = 0
			UNION DISTINCT 
			SELECT DISTINCT hash FROM openconnhash_tmp o
			LEFT JOIN uid_list oi ON o.zeek_uid = oi.zeek_uid
			GROUP BY hash
			HAVING countIf(o.zeek_uid = oi.zeek_uid) = 0
		),
		ip_conns AS (
		-- Get IP connections
		SELECT  hash, src, src_nuid,  dst, dst_nuid, src_local, dst_local,
				countMerge(missing_host_header_count) AS missing_host_count, 
				countMerge(count) as conn_count,
				0 as open_count,     -- only used in openconn/openhttp
				0 as proxy_count,    -- only used in sni/openhttp
				sumMerge(total_duration) as total_duration,
				toFloat64(0) as open_duration,  -- only used for openconn/openhttp
				arraySort(groupArrayMerge(86400)(ts_list)) as ts_list,
				uniqExactMerge(unique_ts_count) as ts_unique, -- gets unique timestamp count for uconns
				arraySort(groupArrayMerge(86400)(src_ip_bytes_list)) as bytes,
				sumMerge(total_ip_bytes) as total_bytes,
				maxMerge(last_seen) as last_seen,
				minMerge(first_seen) as first_seen
		FROM uconn
		-- Limit IP connections to just connections not used by a SNI beacon
		RIGHT JOIN filtered_hashes USING hash
		-- Limit query to the last 24 hours of data
		WHERE hour >= toStartOfHour(fromUnixTimestamp(:min_ts))
		GROUP BY hash, src, src_nuid, dst, dst_nuid, src_local, dst_local

		UNION ALL

		-- Get open connections
		SELECT  hash, src, src_nuid, dst, dst_nuid, src_local, dst_local,
				countIf(missing_host_header = true) AS missing_host_count, 
				0 as conn_count, -- open connections use open_count
				count() as open_count,
				0 as proxy_count, 
				toFloat64(0) as total_duration, -- open connections use open_duration
				sum(duration) as open_duration,
				[] as ts_list, -- set to zero/empty since we aren't using open connections for beaconing
				0 as ts_unique,
				[] as bytes,
				sum(src_ip_bytes + dst_ip_bytes) as total_bytes,
				min(ts) AS first_seen,
				max(ts) AS last_seen
		FROM openconn
		RIGHT JOIN filtered_hashes USING hash -- exclude SNI connections
		GROUP BY hash, src, src_nuid, dst, dst_nuid, src_local, dst_local
		),
		-- Aggregate data between all union groups
		totaled_ipconns AS (
			SELECT  hash, src, src_nuid, dst, dst_nuid, src_local, dst_local,
				-- if(t.ip != '::', true, false) AS on_threat_intel,
				-- prevalence_total, 
				-- toFloat32(prevalence_total / {network_size:UInt64}) AS prevalence,
				-- min(if({rolling:Bool}, h.first_seen, i.first_seen)) AS first_seen_historical,
				sum(missing_host_count) as missing_host_count,
				sum(conn_count) as count,
				sum(open_count) as open_count,
				sum(proxy_count) as proxy_count,
				sum(total_duration + open_duration) as total_duration,
				sum(open_duration) as open_total_duration,
				groupArrayArray(86400)(ts_list) as ts_list,
				-- since the uniqExact AggregateFunctions are defined on uconn and usni (2 separate materialized views),
				-- the unique ts count doesn't represent the unique set between both uconn and usni, so we must take the max of these two
				-- and as long as that value is greater than the unique_connection_threshold (checked when we loop through the results), 
				-- we will send it to the beacon analysis workers
				max(ts_unique) as ts_unique,
				groupArrayArray(86400)(bytes) as bytes,
				sum(total_bytes) as total_bytes,
				max(last_seen) as last_seen,
				min(first_seen) as first_seen
				-- any(po.port_proto_service) as port_proto_service
		FROM ip_conns
		-- LEFT JOIN prevalence_counts p ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = p.ip
		-- LEFT JOIN metadatabase.threat_intel t ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = t.ip
		-- LEFT JOIN port_proto po ON i.hash = po.hash
		-- LEFT JOIN historical h ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = h.ip
		GROUP BY hash, src, src_nuid, dst, dst_nuid, src_local, dst_local
		),
		-- historical and port_proto are split out here instead of just being joined on at the end in order to avoid
		-- multiplying the results (cartesian product)
		historical AS (
			SELECT min(first_seen) AS first_seen, ip 
			FROM metadatabase.historical_first_seen h
			LEFT JOIN ip_conns i ON h.ip = multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) 
			GROUP BY ip
		),
		port_proto AS (
			SELECT hash, groupUniqArray(20)(port_proto_service) AS port_proto_service FROM (
				SELECT DISTINCT hash, concat(po.dst_port, ':', po.proto, ':', po.service) as port_proto_service
				FROM port_info po
				LEFT JOIN ip_conns i ON i.hash = po.hash
				WHERE hour >= toStartOfHour(fromUnixTimestamp(:min_ts))
				UNION DISTINCT
				SELECT DISTINCT hash, concat(dst_port, ':', proto, ':', service) as port_proto_service
				FROM openconn
				WHERE missing_host_header = false
			)
			GROUP BY hash
		)
		SELECT  i.hash AS hash, i.src as src, i.src_nuid as src_nuid, i.dst as dst, i.dst_nuid as dst_nuid, 
				'ip' AS beacon_type,
				missing_host_count,
				count,
				open_count,
				proxy_count,
				total_duration,
				open_total_duration,
				ts_list,
				ts_unique,
				bytes,
				total_bytes,
				last_seen,
				if(t.ip != '::', true, false) AS on_threat_intel,
				prevalence_total, 
				toFloat32(prevalence_total / :network_size) AS prevalence,
				if(:rolling, h.first_seen, i.first_seen) AS first_seen_historical,
				po.port_proto_service as port_proto_service
		FROM totaled_ipconns i 
		LEFT JOIN prevalence_counts p ON if(src_local = true, i.dst, i.src) = p.ip
		-- LEFT JOIN prevalence_counts p ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = p.ip
		LEFT JOIN metadatabase.threat_intel t ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = t.ip
		LEFT JOIN port_proto po ON i.hash = po.hash
		LEFT JOIN historical h ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = h.ip
		