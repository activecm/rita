package analysis

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/progressbar"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type AnalysisResult struct {
	// Unique connections
	Hash                util.FixedString `ch:"hash"`
	Src                 net.IP           `ch:"src"`
	SrcNUID             uuid.UUID        `ch:"src_nuid"`
	Dst                 net.IP           `ch:"dst"`
	DstNUID             uuid.UUID        `ch:"dst_nuid"`
	FQDN                string           `ch:"fqdn"`
	BeaconType          string           `ch:"beacon_type"` // (sni, ip, dns)
	Count               uint64           `ch:"count"`
	ProxyCount          uint64           `ch:"proxy_count"`
	OpenCount           uint64           `ch:"open_count"`
	TSUnique            uint64           `ch:"ts_unique"` // number of unique timestamps
	TSList              []uint32         `ch:"ts_list"`
	TotalDuration       float64          `ch:"total_duration"`
	OpenTotalDuration   float64          `ch:"open_total_duration"`
	BytesList           []float64        `ch:"bytes"` //TODO: do we need to change this since bytes are now uint64?
	TotalBytes          uint64           `ch:"total_bytes"`
	PortProtoService    []string         `ch:"port_proto_service"`
	FirstSeenHistorical time.Time        `ch:"first_seen_historical"`
	LastSeen            time.Time        `ch:"last_seen"`
	ServerIPs           []net.IP         `ch:"server_ips"` // array of unique destination IPs for SNI conns
	ProxyIPs            []net.IP         `ch:"proxy_ips"`  // array of unique proxy (destination IPs) for SNI conns
	MissingHostCount    uint64           `ch:"missing_host_count"`

	// C2 OVER DNS Connection Info
	HasC2OverDNSDirectConnectionsModifier bool `ch:"has_c2_direct_conns_mod"`

	// Prevalence
	PrevalenceTotal uint64  `ch:"prevalence_total"`
	Prevalence      float64 `ch:"prevalence"`

	// C2 over DNS
	TLD            string `ch:"tld"`
	SubdomainCount uint64 `ch:"subdomain_count"`

	// Threat Intel
	OnThreatIntel bool `ch:"on_threat_intel"`
}

func (analyzer *Analyzer) Spagoop(ctx context.Context) error {
	logger := zlog.GetLogger()

	// record start time
	start := time.Now()

	queryGroup, ctx := errgroup.WithContext(ctx)

	// create progress bars
	bars := progressbar.New(ctx, []*progressbar.ProgressBar{
		progressbar.NewBar("SNI Connection Analysis", 1, progress.New(progress.WithDefaultGradient())),
		progressbar.NewBar("IP Connection Analysis ", 2, progress.New(progress.WithDefaultGradient())),
		progressbar.NewBar("DNS Analysis           ", 3, progress.New(progress.WithDefaultGradient())),
	}, []progressbar.Spinner{})

	// if !analyzer.minTS.IsZero() && !analyzer.maxTS.IsZero() {
	logger.Debug().Msg("Starting to get unique SNI connections")

	queryGroup.Go(func() error {
		// get the unique connections from the database
		err := analyzer.ScoopSNIConns(ctx, bars)
		// record end time
		end := time.Since(start)
		// print the time it took to finish
		logger.Debug().Str("elapsed", fmt.Sprintf("%1.2fs", end.Seconds())).Msg("FINISHED SNI BEACON QUERY")
		return err
	})

	logger.Debug().Msg("Starting to get unique IP connections")

	queryGroup.Go(func() error {
		// get the unique connections from the database
		err := analyzer.ScoopIPConns(ctx, bars)
		// record end time
		end := time.Since(start)
		// log the time it took to finish
		logger.Debug().Str("elapsed", fmt.Sprintf("%1.2fs", end.Seconds())).Msg("FINISHED IP BEACON QUERY")
		return err
	})

	// }

	logger.Debug().Msg("Starting to get DNS connections")

	queryGroup.Go(func() error {
		// get the unique connections from the database
		err := analyzer.ScoopDNS(ctx, bars)
		// record end time
		end := time.Since(start)
		// print the time it took to finish
		logger.Debug().Str("elapsed", fmt.Sprintf("%1.2fs", end.Seconds())).Msg("FINISHED EXPLODED DNS QUERY")
		return err
	})

	queryGroup.Go(func() error {
		_, err := bars.Run()
		if err != nil {
			logger.Error().Err(err).Msg("error running program")
		}
		return err
	})

	// // wait for the uconn queries and check if any exited with an error
	// // Note: If any of the g.Go routines return an error, then the context will be cancelled
	// // and other goroutines can exit if they listen for the context cancellation (ctx.Done())
	if err := queryGroup.Wait(); err != nil {
		close(analyzer.UconnChan)
		logger.Error().Err(err).Msg("could not perform uconn spagoop")
		return err
	}

	// close uconn channel to signal that all uconns have been sent
	close(analyzer.UconnChan)

	logger.Debug().Msg("Finished getting uconns")
	return nil
}

func (analyzer *Analyzer) ScoopSNIConns(ctx context.Context, bars *tea.Program) error {
	logger := zlog.GetLogger()

	// initialize progress bar variables
	var totalSNI uint64
	// get total number of unique hashes between sni and opensni
	err := analyzer.Database.Conn.QueryRow(analyzer.Database.GetContext(), `
		SELECT count() FROM (
			SELECT DISTINCT hash FROM sniconn_tmp
			UNION DISTINCT
			SELECT DISTINCT hash FROM opensniconn_tmp
		)
	`).Scan(&totalSNI)
	if err != nil {
		return err
	}

	// use context to pass a call back for progress and profile info
	chCtx := clickhouse.Context(analyzer.Database.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		// use minTSBeacon because all SNI conns have a matching conn entry and openconn data is not limited by the hour since the tables are truncated before each import
		"min_ts":                      fmt.Sprintf("%d", analyzer.minTSBeacon.UTC().Unix()),
		"unique_connection_threshold": fmt.Sprint(analyzer.Config.Scoring.Beacon.UniqueConnectionThreshold),
		"network_size":                fmt.Sprint(analyzer.networkSize),
		// historical first seen is used for rolling dbs, but if the db is >24hrs old it must use the first seen from the current import due to the ttl on the historical_first_seen table
		"use_historical": strconv.FormatBool(analyzer.Database.Rolling && analyzer.useCurrentTime),
	}))

	rows, err := analyzer.Database.Conn.Query(chCtx, `--sql
	WITH unique_sni AS (
		SELECT DISTINCT hash FROM sniconn_tmp
	),
	prevalence_counts AS (
	    SELECT fqdn, count() as prevalence_total FROM (
			SELECT DISTINCT fqdn, src FROM usni
			WHERE src_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT fqdn, dst AS src FROM usni
			WHERE dst_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			
			UNION DISTINCT 
			
			SELECT DISTINCT host as fqdn, src FROM openhttp
			WHERE src_local
			UNION DISTINCT
			SELECT DISTINCT host as fqdn, dst AS src FROM openhttp
			WHERE dst_local
			
			UNION DISTINCT 
			
			SELECT DISTINCT server_name as fqdn, src FROM openssl
			WHERE src_local
			UNION DISTINCT 
			SELECT DISTINCT server_name as fqdn, dst AS src FROM openssl
			WHERE dst_local

			UNION DISTINCT

			SELECT DISTINCT fqdn, src FROM udns
			WHERE src_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT fqdn, dst AS src FROM udns
			WHERE dst_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
	    )
	    GROUP BY fqdn
	),  
	sniconns AS (
		-- Get SNI connections (HTTP + SSL for a source IP -> destination FQDN pair)
		SELECT hash, src, src_nuid, fqdn, 
			countMerge(count) AS conn_count, 
			countMerge(proxy_count) AS proxy_count,
			0 as open_count,
			sumMerge(total_duration) AS total_duration,
			0 AS open_duration,
			uniqExactMerge(unique_ts_count) AS ts_unique,
			arraySort(groupArrayMerge(86400)(ts_list)) AS ts_list, 
			arraySort(groupArrayMerge(86400)(src_ip_bytes_list)) AS bytes,
			sumMerge(total_ip_bytes) as total_bytes,
			groupUniqArrayMerge(10)(server_ips) AS server_ips, 
			groupUniqArrayMerge(10)(proxy_ips) AS proxy_ips, 
			maxMerge(last_seen) AS last_seen,
			minMerge(first_seen) as first_seen
		FROM usni
		RIGHT JOIN unique_sni USING hash
		-- Limit query to the last 24 hours of data
		WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
		GROUP BY hash, src, src_nuid, fqdn, proxy

		UNION ALL 

		-- Get Open HTTP connections
		SELECT  hash, src, src_nuid, host as fqdn, 
				0 as conn_count, -- openhttp uses open_count
				countIf(method = 'CONNECT') as proxy_count,
				countIf(multi_request = false) as open_count,
				0 as total_duration,
				sum(duration) as open_duration,
				0 as ts_unique, -- set following to zero/empty since openhttp is not included in beaconing
				[] as ts_list, 
				[] as bytes,
				sum(src_ip_bytes + dst_ip_bytes) as total_bytes,
				groupUniqArrayIf(10)(dst, method != 'CONNECT') as server_ips, 
				groupUniqArrayIf(10)(dst, method = 'CONNECT') as proxy_ips,
				max(ts) AS last_seen,
				min(ts) AS first_seen
		FROM openhttp
		-- ignore missing hosts for openhttp, this is automatically handled in usni via MV
		WHERE host != ''
		-- Right join unique HTTP hashes to limit analysis to just the connections that updated in this import
		GROUP BY hash, src, src_nuid, fqdn

		UNION ALL

		-- Get Open SSL connections
		SELECT  hash, src, src_nuid, server_name as fqdn, 
				0 as conn_count, -- openssl uses open_count
				0 as proxy_count, 
				count() as open_count,
				0 as total_duration, -- openssl uses open_duration
				sum(duration) as open_duration,
				0 as ts_unique, -- set following to zero/empty since openssl is not included in beaconing
				[] as ts_list,
				[] as bytes,
				sum(src_ip_bytes + dst_ip_bytes) as total_bytes,
				groupUniqArray(10)(dst) as server_ips,
				[] as proxy_ips,
				max(ts) AS last_seen,
				min(ts) AS first_seen
		FROM openssl
		GROUP BY hash, src, src_nuid, fqdn
	),
	historical AS (
		SELECT min(first_seen) AS first_seen, fqdn 
		FROM metadatabase.historical_first_seen
		LEFT JOIN sniconns USING fqdn
		GROUP BY fqdn
	),
	port_proto AS (
		SELECT hash, groupUniqArray(20)(port_proto_service) AS port_proto_service FROM (
			SELECT DISTINCT hash, concat(po.dst_port, ':', po.proto, ':', po.service) as port_proto_service
			FROM port_info po
			LEFT JOIN sniconns s ON s.hash = po.hash
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT hash, concat(dst_port, ':', proto, ':', service) FROM openhttp
			UNION DISTINCT
			SELECT DISTINCT hash, concat(dst_port, ':', proto, ':', service) FROM openssl
		)
		GROUP BY hash
	),
	-- Aggregate data between all union groups into final structure
	totaled_sniconns AS (
		SELECT s.hash AS hash, s.src AS src, s.src_nuid AS src_nuid, s.fqdn AS fqdn, 
			sum(conn_count) AS count,
			sum(open_count) AS open_count,
			sum(proxy_count) AS proxy_count,
			sum(total_duration + open_duration) AS total_duration,
			sum(open_duration) AS open_total_duration,
			max(ts_unique) AS ts_unique,
			groupArrayArray(86400)(ts_list) AS ts_list,
			groupArrayArray(86400)(bytes) AS bytes,
			sum(total_bytes) AS total_bytes,
			groupUniqArrayArray(10)(server_ips) AS server_ips,
			groupUniqArrayArray(10)(proxy_ips) AS proxy_ips,
			max(s.last_seen) AS last_seen,
			min(s.first_seen) AS first_seen
		FROM sniconns s
		GROUP BY s.hash, s.src, s.src_nuid, s.fqdn
	)
	SELECT  s.hash AS hash, s.src AS src, s.src_nuid AS src_nuid, s.fqdn AS fqdn, 
			if(t.fqdn != '', true, false) AS on_threat_intel,
			prevalence_total, 
      		prevalence_total / {network_size:UInt64} AS prevalence,
			if({use_historical:Bool}, h.first_seen, s.first_seen) AS first_seen_historical,
			'sni' AS beacon_type,
			count,
			open_count,
			proxy_count,
			total_duration,
			open_total_duration,
			ts_unique,
			ts_list,
			bytes,
			total_bytes,
			server_ips,
			proxy_ips,
			last_seen,
			po.port_proto_service as port_proto_service
	FROM totaled_sniconns s
	LEFT JOIN prevalence_counts USING fqdn
	LEFT JOIN metadatabase.threat_intel t ON s.fqdn = t.fqdn 
	LEFT JOIN historical h ON h.fqdn = s.fqdn
	LEFT JOIN port_proto po ON s.hash = po.hash
`)
	if err != nil {
		// return error and cancel all uconn analysis
		return fmt.Errorf("could not retrieve unique SNI connections for analysis: %w", err)
	}
	logger.Debug().Msg("successfully retrieved SNI connections")

	i := uint64(0)
	// loop over the rows
	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling SNI uconns query for analysis")
			rows.Close()
			return ctx.Err()
		default:
			var res AnalysisResult
			if err := rows.ScanStruct(&res); err != nil {
				// return error and cancel all uconn analysis
				return fmt.Errorf("could not read unique SNI connection during analysis: %w", err)
			}
			// send the unique sni connections to the uconn analysis channel
			analyzer.UconnChan <- res
			if i%1000 == 0 {
				bars.Send(progressbar.ProgressMsg{ID: 1, Percent: float64(i / totalSNI)})
			}
			i++
		}
	}
	rows.Close()
	bars.Send(progressbar.ProgressMsg{ID: 1, Percent: 1})
	return nil
}

func (analyzer *Analyzer) ScoopIPConns(ctx context.Context, bars *tea.Program) error {
	logger := zlog.GetLogger()

	totalRows := uint64(0)
	hasSetTotal := false
	chCtx := clickhouse.Context(analyzer.Database.GetContext(), clickhouse.WithProgress(func(p *clickhouse.Progress) {
		// set the total rows for the progress bar
		if !hasSetTotal {
			totalRows = p.Rows
			if totalRows == 0 {
				bars.Send(progressbar.ProgressMsg{ID: 2, Percent: 1})
			}
			hasSetTotal = true
		} else {
			// update the progress bar
			if totalRows > 0 {
				bars.Send(progressbar.ProgressMsg{ID: 2, Percent: float64((totalRows - p.Rows) / totalRows)})
			}
			bars.Send(progressbar.ProgressMsg{ID: 2, Percent: 1})
		}
	}), clickhouse.WithParameters(clickhouse.Parameters{
		// use minTSBeacon because all entries in conn are used in beaconing and openconn data is not limited by the hour since the tables are truncated before each import
		"min_ts":                      fmt.Sprintf("%d", analyzer.minTSBeacon.UTC().Unix()),
		"unique_connection_threshold": fmt.Sprint(analyzer.Config.Scoring.Beacon.UniqueConnectionThreshold),
		"network_size":                fmt.Sprint(analyzer.networkSize),
		// historical first seen is used for rolling dbs, but if the db is >24hrs old it must use the first seen from the current import due to the ttl on the historical_first_seen table
		"use_historical":              strconv.FormatBool(analyzer.Database.Rolling && analyzer.useCurrentTime),
		"long_connection_base_thresh": fmt.Sprintf("%f", float64(analyzer.Config.Scoring.LongConnectionScoreThresholds.Base)),
	}))

	query := `--sql
		WITH unique_http AS (
			SELECT DISTINCT hash FROM sniconn_tmp
			WHERE conn_type = 'http'
		),
		prevalence_counts AS (
			SELECT ip, count() as prevalence_total FROM (
				SELECT DISTINCT if(src_local, dst, src) as ip, if(src_local, src, dst) as internal FROM uconn
				WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
				
				UNION DISTINCT 
				
				SELECT DISTINCT if(src_local, dst, src) as ip, if(src_local, src, dst) as internal FROM openconn
			)
			GROUP BY ip
		),  
		sniconns AS ( -- usni connections that will be beacons or long connections in this import
			SELECT hash, uniqExactMerge(u.unique_ts_count) AS unique_count, countMerge(u.count) AS total_count, sumMerge(total_duration) AS duration
			FROM usni u
			LEFT SEMI JOIN sniconn_tmp t USING hash
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			GROUP BY hash
			-- is beacon or longconn
			HAVING (unique_count >= {unique_connection_threshold:UInt64} AND total_count < 86400) OR
			duration >= {long_connection_base_thresh:Float64}
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
		WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
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
				SELECT DISTINCT hash, if(po.proto = 'icmp', concat(po.proto, ':', po.icmp_type, '/', po.icmp_code), concat(po.dst_port, ':', po.proto, ':', po.service)) as port_proto_service
				FROM port_info po
				LEFT JOIN ip_conns i ON i.hash = po.hash
				WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
				UNION DISTINCT
				SELECT DISTINCT hash, if(proto = 'icmp', concat(proto, ':', src_port, '/', dst_port), concat(dst_port, ':', proto, ':', service)) as port_proto_service
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
				prevalence_total / {network_size:UInt64} AS prevalence,
				if({use_historical:Bool}, h.first_seen, i.first_seen) AS first_seen_historical,
				po.port_proto_service as port_proto_service
		FROM totaled_ipconns i 
		LEFT JOIN prevalence_counts p ON if(src_local = true, i.dst, i.src) = p.ip
		LEFT JOIN metadatabase.threat_intel t ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = t.ip
		LEFT JOIN port_proto po ON i.hash = po.hash
		LEFT JOIN historical h ON multiIf(src_local = true, i.dst, dst_local = true, i.src, i.dst) = h.ip

	`

	rows, err := analyzer.Database.Conn.Query(chCtx, query)
	if err != nil {
		// return error and cancel all uconn analysis
		return fmt.Errorf("could not retrieve unique IP connections for analysis: %w", err)
	}
	logger.Debug().Msg("successsfully retrieved IP connections")
	// loop over the rows
	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling IP uconns query for analysis")
			rows.Close()
			return ctx.Err()
		default:
			var res AnalysisResult
			if err := rows.ScanStruct(&res); err != nil {
				// return error and cancel all uconn analysis
				return fmt.Errorf("could not read IP connection during analysis: %w", err)
			}

			// send the unique ip connection to the uconn analysis channel
			analyzer.UconnChan <- res
		}
	}
	rows.Close()
	return nil
}

func (analyzer *Analyzer) ScoopDNS(ctx context.Context, bars *tea.Program) error {
	logger := zlog.GetLogger()

	totalRows := uint64(0)
	hasSetTotal := false

	// use context to pass a call back for progress and profile info
	chCtx := clickhouse.Context(analyzer.Database.GetContext(), clickhouse.WithProgress(func(p *clickhouse.Progress) {
		// set the total rows for the progress bar
		if !hasSetTotal {
			totalRows = p.Rows
			if totalRows == 0 {
				bars.Send(progressbar.ProgressMsg{ID: 3, Percent: 1})
			}
			hasSetTotal = true
		} else {
			// update the progress bar
			if totalRows > 0 {
				bars.Send(progressbar.ProgressMsg{ID: 3, Percent: float64((totalRows - p.Rows) / totalRows)})
			}
			bars.Send(progressbar.ProgressMsg{ID: 3, Percent: 1})
		}

	}), clickhouse.WithParameters(clickhouse.Parameters{
		// use minTS (not minTSBeacon) because DNS logs don't get correlated with conn logs
		"min_ts":              fmt.Sprintf("%d", analyzer.minTS.UTC().Unix()),
		"subdomain_threshold": fmt.Sprint(analyzer.Config.Scoring.C2ScoreThresholds.Base),
		// historical first seen is used for rolling dbs, but if the db is >24hrs old it must use the first seen from the current import due to the ttl on the historical_first_seen table
		"use_historical": strconv.FormatBool(analyzer.Database.Rolling && analyzer.useCurrentTime),
		"network_size":   fmt.Sprint(analyzer.networkSize),
	}))

	rows, err := analyzer.Database.Conn.Query(chCtx, `--sql
		-- use only the domains from this import to reduce computation cost
		WITH unique_tld AS (
			SELECT DISTINCT tld FROM dns_tmp
		), 
		prevalence_counts AS (
			SELECT tld, count() AS prevalence_total FROM (
				SELECT DISTINCT cutToFirstSignificantSubdomain(fqdn) as tld, src FROM usni
				WHERE src_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
				UNION DISTINCT
				SELECT DISTINCT cutToFirstSignificantSubdomain(fqdn) as tld, dst AS src FROM usni
				WHERE dst_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
				
				UNION DISTINCT 
				
				SELECT DISTINCT cutToFirstSignificantSubdomain(host) as tld, src FROM openhttp
				WHERE src_local
				UNION DISTINCT
				SELECT DISTINCT cutToFirstSignificantSubdomain(host) as tld, dst AS src FROM openhttp
				WHERE dst_local
				
				UNION DISTINCT 
				
				SELECT DISTINCT cutToFirstSignificantSubdomain(server_name) as tld, src FROM openssl
				WHERE src_local
				UNION DISTINCT 
				SELECT DISTINCT cutToFirstSignificantSubdomain(server_name) as tld, dst AS src FROM openssl
				WHERE dst_local

				UNION DISTINCT

				SELECT DISTINCT tld, src FROM udns
				WHERE src_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
				UNION DISTINCT
				SELECT DISTINCT tld, dst AS src FROM udns
				WHERE dst_local AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			)
			GROUP BY tld
		),  
		-- grab the last seen dates for the domains from this import
		unique_dns AS (
			SELECT tld, maxMerge(last_seen) as last_seen, minMerge(first_seen) as first_seen from udns
			-- limiting the scope to just the domains in this import here 
			-- has significant performance benefits as opposed to doing it later in the query
			RIGHT JOIN unique_tld USING tld
			GROUP BY tld
		),
		sussy_subdomains AS (
			-- get all tlds with more than 100 subdomains
			SELECT tld, uniqExactMerge(subdomains) as subdomain_count FROM exploded_dns
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			GROUP BY tld
			HAVING subdomain_count >= 100
		-- get all the resolved ips for the tld
		), resolved_ips AS (
			SELECT DISTINCT resolved_ip, tld FROM pdns
			RIGHT JOIN sussy_subdomains USING tld
			WHERE day >= toStartOfDay(fromUnixTimestamp({min_ts:Int64}))
		-- get all source ips that made a connection to the resolved ips
		), direct_connections AS (
			SELECT tld, src as direct_conn FROM uconn u
			RIGHT JOIN resolved_ips r ON u.dst = r.resolved_ip
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
		-- get all systems that performed a dns query to the tld
		), queried_by AS (
			SELECT tld, src as queried FROM udns
			INNER JOIN sussy_subdomains USING tld
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
		-- keep tlds which had zero non-dns-server ips in direct connections
		), queried_by_count AS (
			SELECT tld, count() as qcount FROM queried_by
			GROUP BY tld
		), direct_conns_modifier AS (
			-- tld has modifier if queried count == 0 or if 
			SELECT ddx.tld AS tld, greatest(if(qc.qcount > 0, 0, 1), 1 - inverse_has_mod) AS has_mod FROM (
				-- direct conns mod checks if there are any IPs in queried that are not also in direct_conns
				-- if there is an IP in queried that isn't in direct_conns, then q.queried is empty
				-- max will return 1 if there was at least 1 ip that wasn't in direct conns
				SELECT d.tld AS tld, max(empty(q.queried)) AS inverse_has_mod FROM direct_connections d
				LEFT JOIN queried_by q ON d.tld = q.tld AND d.direct_conn = q.queried
				GROUP BY tld
			) ddx
			LEFT JOIN queried_by_count qc ON qc.tld = ddx.tld
		),
		totaled_exploded AS (
			SELECT tld, uniqExactMerge(subdomains) AS subdomain_count
			FROM exploded_dns
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			GROUP BY tld
			HAVING subdomain_count >= {subdomain_threshold:Int32}
		),
		historical AS (
			SELECT min(first_seen) AS first_seen, cutToFirstSignificantSubdomain(fqdn) as tld 
			-- SELECT minMerge(first_seen) AS first_seen, cutToFirstSignificantSubdomain(fqdn) as tld 
			FROM metadatabase.historical_first_seen
			INNER JOIN totaled_exploded USING tld
			GROUP BY tld
		)
		-- get the subdomain counts and the last seen count for each tld
		SELECT e.tld AS tld, e.subdomain_count as subdomain_count, 
			'dns' AS beacon_type,
			 u.last_seen as last_seen,
			prevalence_total, 
			if(dm.has_mod > 0, true, false) as has_c2_direct_conns_mod,
			prevalence_total / {network_size:UInt64} AS prevalence,
			-- use the historical first seen value if this dataset is rolling and <= 24 hours old
			if({use_historical:Bool}, h.first_seen, u.first_seen) AS first_seen_historical,
			if(cutToFirstSignificantSubdomain(t.fqdn) != '', true, false) AS on_threat_intel
		FROM totaled_exploded e
		INNER JOIN unique_dns u ON e.tld = u.tld
		LEFT JOIN prevalence_counts p ON e.tld = p.tld
		LEFT JOIN historical h ON e.tld = h.tld
		LEFT JOIN direct_conns_modifier dm ON e.tld = dm.tld
		LEFT JOIN metadatabase.threat_intel t ON e.tld = cutToFirstSignificantSubdomain(t.fqdn)	
	`)
	if err != nil {
		// return error and cancel all uconn analysis
		return fmt.Errorf("could not retrieve unique exploded domains for analysis: %w", err)
	}
	logger.Debug().Msg("successfully retrieved exploded dns")
	// loop over the rows
	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling exploded dns query for analysis")
			rows.Close()
			return ctx.Err()
		default:
			var res AnalysisResult
			if err := rows.ScanStruct(&res); err != nil {
				// return error and cancel all uconn analysis
				return fmt.Errorf("could not read exploded dns during analysis: %w", err)
			}
			// send the unique ip connection to the uconn analysis channel
			analyzer.UconnChan <- res
		}
	}
	rows.Close()
	return nil
}
