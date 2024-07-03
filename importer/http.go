package importer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/activecm/rita/config"
	"github.com/activecm/rita/database"
	"github.com/activecm/rita/importer/zeektypes"
	"github.com/activecm/rita/logger"
	"github.com/activecm/rita/progressbar"
	"github.com/activecm/rita/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
)

type HTTPEntry struct {
	ImportTime   time.Time        `ch:"import_time"`
	ZeekUID      util.FixedString `ch:"zeek_uid"`
	Hash         util.FixedString `ch:"hash"`
	Timestamp    time.Time        `ch:"ts"`
	Src          net.IP           `ch:"src"`
	Dst          net.IP           `ch:"dst"`
	SrcNUID      uuid.UUID        `ch:"src_nuid"`
	DstNUID      uuid.UUID        `ch:"dst_nuid"`
	MultiRequest bool             `ch:"multi_request"`
	SrcPort      uint16           `ch:"src_port"`
	DstPort      uint16           `ch:"dst_port"`
	Duration     float64          `ch:"duration"`
	SrcLocal     bool             `ch:"src_local"`
	DstLocal     bool             `ch:"dst_local"`
	SrcBytes     int64            `ch:"src_bytes"`
	DstBytes     int64            `ch:"dst_bytes"`
	SrcIPBytes   int64            `ch:"src_ip_bytes"`
	DstIPBytes   int64            `ch:"dst_ip_bytes"`
	SrcPackets   int64            `ch:"src_packets"`
	DstPackets   int64            `ch:"dst_packets"`
	Proto        string           `ch:"proto"`
	Service      string           `ch:"service"`
	ConnState    string           `ch:"conn_state"`
	TransDepth   uint16           `ch:"trans_depth"`
	Method       string           `ch:"method"`
	Host         string           `ch:"host"`
	URI          string           `ch:"uri"`
	Referrer     string           `ch:"referrer"`
	HTTPVersion  string           `ch:"http_version"`
	UserAgent    string           `ch:"useragent"`
	Origin       string           `ch:"origin"`
	StatusCode   int64            `ch:"status_code"`
	StatusMsg    string           `ch:"status_msg"`
	InfoCode     int64            `ch:"info_code"`
	InfoMsg      string           `ch:"info_msg"`
	Username     string           `ch:"username"`
	Password     string           `ch:"password"`
	SrcFUIDs     []string         `ch:"src_fuids"`
	SrcFileNames []string         `ch:"src_file_names"`
	SrcMIMETypes []string         `ch:"src_mime_types"`
	DstFUIDs     []string         `ch:"dst_fuids"`
	DstFileNames []string         `ch:"dst_file_names"`
	DstMIMETypes []string         `ch:"dst_mime_types"`
}

// parseHTTP listens on a channel of raw http/openhttp log records, formats them and sends them to be linked with conn/openconn records and written to the database
// func parseHTTP(http <-chan zeektypes.HTTP, zeekUIDMap cmap.ConcurrentMap[string, *ZeekUIDRecord], uHTTPMap cmap.ConcurrentMap[string, *UniqueFQDN], output chan database.Data, trackUIDLock *sync.Mutex, numHTTP *uint64) {
func parseHTTP(http <-chan zeektypes.HTTP, output chan database.Data, connOutput chan database.Data, importID util.FixedString, trackUIDLock *sync.Mutex, importTime time.Time, numHTTP *uint64, numConn *uint64) {
	logger := logger.GetLogger()

	// loop over raw http/openhttp channel
	for h := range http {

		// parse raw record as an http/open http entry
		entry, err := formatHTTPRecord(&h, importTime)
		if err != nil {
			logger.Warn().Err(err).
				Str("log_path", h.LogPath).
				Str("zeek_uid", h.UID).
				Str("timestamp", (time.Unix(int64(h.TimeStamp), 0)).String()).
				Str("src", h.Source).
				Str("dst", h.Destination).
				Str("fqdn", h.Host).
				Str("uri", h.URI).
				Send()
			continue
		}

		// entry was subject to filtering
		if entry == nil {
			continue
		}

		if entry.Host == "" {
			atomic.AddUint64(numConn, 1)
		} else {
			atomic.AddUint64(numHTTP, 1)
		}

		output <- entry
	}

}

// formatHTTPRecord takes a raw http record and formats it into the structure needed by the database
func formatHTTPRecord(parseHTTP *zeektypes.HTTP, importTime time.Time) (*HTTPEntry, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}
	// get source destination pair for connection record
	src := parseHTTP.Source
	dst := parseHTTP.Destination

	// parse addresses into binary format
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)

	// verify that both addresses were able to be parsed successfully
	if (srcIP == nil) || (dstIP == nil) {
		return nil, errors.New(errParseSrcDst)
	}

	// parse host
	fqdn := parseHTTP.Host

	// check if destination is a proxy server based on HTTP method
	dstIsProxy := (parseHTTP.Method == "CONNECT")

	// if the HTTP method is CONNECT, then the srcIP is communicating
	// to an FQDN through the dstIP proxy. We need to handle that
	// as a special case here so that we don't filter internal->internal
	// connections if the dstIP is an internal IP because the dstIP
	// is an intermediary and not the final destination.
	//
	// The dstIP filter check is not included for proxy connections either
	// because it isn't really the destination and it doesn't seem to make
	// sense in this context to check for it. If the proxy IP is external,
	// this will also allow a user to filter results from other modules
	// (e.g., beacons), where false positives might arise due to the proxy IP
	// appearing as a destination, while still allowing for processing that
	// data for the proxy modules

	srcLocal := cfg.Filter.CheckIfInternal(srcIP)
	dstLocal := cfg.Filter.CheckIfInternal(dstIP)

	if dstIsProxy {

		if cfg.Filter.FilterDomain(fqdn) || cfg.Filter.FilterSingleIP(srcIP) {

			return nil, nil
		}
		fqdnAsIPAddress := net.ParseIP(fqdn)

		if fqdnAsIPAddress != nil && dstLocal && cfg.Filter.FilterConnPair(srcIP, fqdnAsIPAddress) {
			return nil, nil
		}
	} else if cfg.Filter.FilterDomain(fqdn) || cfg.Filter.FilterConnPair(srcIP, dstIP) ||
		// filter out connections where the src is external if the host isn't missing
		(cfg.Filter.FilterSNIPair(srcIP) && parseHTTP.Host != "") {
		return nil, nil
	}

	srcNUID := util.ParseNetworkID(srcIP, parseHTTP.AgentUUID)
	dstNUID := util.ParseNetworkID(dstIP, parseHTTP.AgentUUID)

	zeekUID, err := util.NewFixedStringHash(parseHTTP.UID)
	if err != nil {
		return nil, err
	}

	hash, err := util.NewFixedStringHash(srcIP.To16().String(), srcNUID.String(), dstIP.To16().String(), dstNUID.String(), fqdn)
	if err != nil {
		return nil, err
	}

	entry := &HTTPEntry{
		ImportTime:   importTime,
		ZeekUID:      zeekUID,
		Hash:         hash,
		Timestamp:    time.Unix(int64(parseHTTP.TimeStamp), 0),
		Src:          srcIP,
		Dst:          dstIP,
		SrcNUID:      srcNUID,
		DstNUID:      dstNUID,
		SrcPort:      uint16(parseHTTP.SourcePort),
		DstPort:      uint16(parseHTTP.DestinationPort),
		SrcLocal:     srcLocal,
		DstLocal:     dstLocal,
		TransDepth:   uint16(parseHTTP.TransDepth),
		Method:       parseHTTP.Method,
		Host:         fqdn,
		URI:          parseHTTP.URI,
		Referrer:     parseHTTP.Referrer,
		HTTPVersion:  parseHTTP.Version,
		UserAgent:    parseHTTP.UserAgent,
		Origin:       parseHTTP.Origin,
		StatusCode:   parseHTTP.StatusCode,
		StatusMsg:    parseHTTP.StatusMsg,
		InfoCode:     parseHTTP.InfoCode,
		InfoMsg:      parseHTTP.InfoMsg,
		Username:     parseHTTP.UserName,
		Password:     parseHTTP.Password,
		SrcFUIDs:     parseHTTP.OrigFuids,
		SrcFileNames: parseHTTP.OrigFilenames,
		SrcMIMETypes: parseHTTP.OrigMimeTypes,
		DstFUIDs:     parseHTTP.RespFuids,
		DstFileNames: parseHTTP.RespFilenames,
		DstMIMETypes: parseHTTP.RespMimeTypes,
	}

	return entry, nil
}

func (importer *Importer) writeLinkedHTTP(ctx context.Context, progress *tea.Program, barID int, httpWriter, connWriter *database.BulkWriter, open bool) error { //httpWriter chan database.Data, connWriter chan database.Data
	logger := logger.GetLogger()
	cfg, err := config.GetConfig()
	if err != nil {
		return err
	}

	tmpTable := "http_tmp"
	tableB := "conn_tmp"
	if open {
		tmpTable = "openhttp_tmp"
		tableB = "openconn_tmp"
	}

	chCtx := importer.Database.QueryParameters(clickhouse.Parameters{
		"tmp_table": tmpTable,
		"table_b":   tableB,
	})

	var totalHTTP uint64
	err = importer.Database.Conn.QueryRow(chCtx, `
		SELECT count() FROM {tmp_table:Identifier}
	`).Scan(&totalHTTP)
	if err != nil {
		return err
	}

	rows, err := importer.Database.Conn.Query(chCtx, `
	WITH http_base AS (
		SELECT zeek_uid, ts, src, src_nuid, dst, dst_nuid, src_port, dst_port, host, src_local, dst_local, useragent, method,
			   uri, referrer, http_version, trans_depth, origin, 
			   status_code, status_msg, info_code, info_msg, username, password,
			   src_fuids, src_file_names, src_mime_types, dst_fuids, dst_mime_types,
			   row_number() OVER (PARTITION BY zeek_uid ORDER BY ts DESC) AS rn
		FROM {tmp_table:Identifier}
	) 
	SELECT 
		h.zeek_uid as zeek_uid, c.hash as hash, c.ts AS ts, h.src_local as src_local, h.dst_local as dst_local,
		h.src as src, h.src_nuid as src_nuid, h.dst as dst, h.dst_nuid as dst_nuid, h.src_port as src_port, h.dst_port as dst_port,
		h.host as host, h.useragent as useragent, h.method as method, h.uri as uri, h.referrer as referrer, h.http_version as http_version,
		h.trans_depth as trans_depth, h.origin as origin, h.status_code as status_code, h.status_msg as status_msg, h.info_code as info_code,
		h.info_msg as info_msg, h.username as username, h.password as password, h.src_fuids as src_fuids,
		h.src_file_names as src_file_names, h.src_mime_types as src_mime_types, h.dst_fuids as dst_fuids, h.dst_mime_types as dst_mime_types,
		-- set proto and service regardless of whether it was linked already or not
		-- since multi-requests can use different dst ports and still have the same UID, so
		-- it is useful to be able to see the dst ports coming from multi request entries as well
		c.proto as proto, c.service as service,
		if( h.rn = 1, c.src_ip_bytes, 0) as src_ip_bytes,
		if( h.rn = 1, c.dst_ip_bytes, 0) as dst_ip_bytes,
		if( h.rn = 1, c.src_bytes, 0) as src_bytes,
		if( h.rn = 1, c.dst_bytes, 0) as dst_bytes,
		if( h.rn = 1, c.duration, 0) as duration,
		if( h.rn = 1, c.conn_state, '') as conn_state,
		if( h.rn = 1, c.src_packets, 0) as src_packets,
		if( h.rn = 1, c.dst_packets, 0) as dst_packets,
		if( h.rn > 1,true,  0) as multi_request
	FROM http_base h
	INNER JOIN {table_b:Identifier} c USING zeek_uid
	WHERE h.rn <= 20
`)
	if err != nil {
		return err
	}
	i := 0
	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling HTTP connection linking")
			rows.Close()
			return ctx.Err()
		default:
			var entry HTTPEntry

			err := rows.ScanStruct(&entry)
			if err != nil {
				return err
			}
			i++
			// update progress bar every 1000 entries
			if i%1000 == 0 {
				progress.Send(progressbar.ProgressMsg{ID: barID, Percent: float64(float64(i) / float64(totalHTTP))})
			}
			entry.ImportTime = importer.Database.ImportStartedAt

			hash, err := util.NewFixedStringHash(entry.Src.To16().String(), entry.SrcNUID.String(), entry.Host)
			if err != nil {
				return err
			}

			switch {
			case entry.Host == "":
				ignore := cfg.Filter.FilterConnPair(entry.Src, entry.Dst)
				if ignore {
					continue
				}

				icmpType, icmpCode := -1, -1

				if entry.Proto == "icmp" {
					icmpType = int(entry.SrcPort)
					icmpCode = int(entry.DstPort)
				}

				connEntry := &ConnEntry{
					ZeekUID:              entry.ZeekUID,
					ImportID:             importer.ImportID,
					ImportTime:           entry.ImportTime,
					Hash:                 entry.Hash,
					Timestamp:            entry.Timestamp,
					Src:                  entry.Src,
					Dst:                  entry.Dst,
					SrcNUID:              entry.SrcNUID,
					DstNUID:              entry.DstNUID,
					SrcPort:              entry.SrcPort,
					DstPort:              entry.DstPort,
					MissingHostHeader:    true,            // this field MUST be set to true
					MissingHostUseragent: entry.UserAgent, // this field MUST be set
					SrcLocal:             entry.SrcLocal,
					DstLocal:             entry.DstLocal,
					ICMPType:             icmpType,
					ICMPCode:             icmpCode,
				}
				connWriter.WriteChannel <- connEntry
			default:
				entry.Hash = hash
				httpWriter.WriteChannel <- &entry
			}
		}
	}
	rows.Close()
	progress.Send(progressbar.ProgressMsg{ID: barID, Percent: 1})

	return nil
}
