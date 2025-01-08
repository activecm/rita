package importer

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/importer/zeektypes"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/progressbar"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
)

var errParseSrcDst = "unable to parse valid ip address pair from conn log entry, skipping entry"

type ConnEntry struct {
	ImportTime           time.Time        `ch:"import_time"`
	ZeekUID              util.FixedString `ch:"zeek_uid"`
	ImportID             util.FixedString `ch:"import_id"`
	Filtered             bool             `ch:"filtered"`
	Hash                 util.FixedString `ch:"hash"`
	Timestamp            time.Time        `ch:"ts"`
	Src                  net.IP           `ch:"src"`
	Dst                  net.IP           `ch:"dst"`
	SrcNUID              uuid.UUID        `ch:"src_nuid"`
	DstNUID              uuid.UUID        `ch:"dst_nuid"`
	SrcPort              uint16           `ch:"src_port"`
	DstPort              uint16           `ch:"dst_port"`
	MissingHostHeader    bool             `ch:"missing_host_header"`    // used to mark HTTP entries that have a missing host header
	MissingHostUseragent string           `ch:"missing_host_useragent"` // useragent for connections that have a missing host header
	Proto                string           `ch:"proto"`
	Service              string           `ch:"service"`
	Duration             float64          `ch:"duration"`
	SrcLocal             bool             `ch:"src_local"`
	DstLocal             bool             `ch:"dst_local"`
	ICMPType             int              `ch:"icmp_type"`
	ICMPCode             int              `ch:"icmp_code"`
	SrcBytes             uint64           `ch:"src_bytes"`
	DstBytes             uint64           `ch:"dst_bytes"`
	SrcIPBytes           uint64           `ch:"src_ip_bytes"`
	DstIPBytes           uint64           `ch:"dst_ip_bytes"`
	SrcPackets           uint64           `ch:"src_packets"`
	DstPackets           uint64           `ch:"dst_packets"`
	ConnState            string           `ch:"conn_state"`
	MissedBytes          uint64           `ch:"missed_bytes"`
	ZeekHistory          string           `ch:"zeek_history"`
}

type UniqueConn struct {
	Hash      util.FixedString `ch:"hash"`
	Src       net.IP           `ch:"src"`
	Dst       net.IP           `ch:"dst"`
	SrcNUID   uuid.UUID        `ch:"src_nuid"`
	DstNUID   uuid.UUID        `ch:"dst_nuid"`
	ConnCount uint64
	ConnType  string
}

type ZeekUIDRecord struct {
	UID               util.FixedString
	Timestamp         time.Time
	UsedByFQDNBeacon  bool
	UsedByDNS         bool
	LinkedToHTTPEntry bool
	NumUsedByHTTP     int
	Duration          float64
	SrcBytes          uint64
	DstBytes          uint64
	SrcIPBytes        uint64
	DstIPBytes        uint64
	SrcPackets        uint64
	DstPackets        uint64
	ConnState         string
	Proto             string
	Service           string
}

// parseConn listens on a channel of raw conn/openconn log records, formats them and sends them to be written to the database
func parseConn(cfg *config.Config, conn <-chan zeektypes.Conn, output chan<- database.Data, importID util.FixedString, importTime time.Time, numConns *uint64) {
	logger := zlog.GetLogger()

	// loop over raw conn/openconn channel
	for c := range conn {

		// parse raw record as a conn/openconn entry
		entry, err := formatConnRecord(cfg, &c, importID, importTime)
		if err != nil {
			logger.Warn().Err(err).
				Str("log_path", c.LogPath).
				Str("zeek_uid", c.UID).
				Str("timestamp", (time.Unix(int64(c.TimeStamp), 0)).String()).
				Str("src", c.Source).
				Str("dst", c.Destination).
				Send()

			continue
		}

		// entry was subject to filtering
		if entry == nil {
			continue
		}

		output <- entry // send to log writer
		if !entry.Filtered {
			atomic.AddUint64(numConns, 1) // increment record counter
		}
	}

}

// formatConnRecord takes a raw conn record and formats it into the structure needed by the database
func formatConnRecord(cfg *config.Config, parseConn *zeektypes.Conn, importID util.FixedString, importTime time.Time) (*ConnEntry, error) { // filter filter

	// get source destination pair for connection record
	src := parseConn.Source
	dst := parseConn.Destination

	// parse addresses into binary format
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)

	// verify that both addresses were parsed successfully
	if (srcIP == nil) || (dstIP == nil) {
		return nil, errors.New(errParseSrcDst)
	}

	// check if the connection is an icmp connection
	icmpType, icmpCode := -1, -1

	if parseConn.Proto == "icmp" {
		icmpType = parseConn.SourcePort
		icmpCode = parseConn.DestinationPort
	}

	srcNUID := util.ParseNetworkID(srcIP, parseConn.AgentUUID)
	dstNUID := util.ParseNetworkID(dstIP, parseConn.AgentUUID)

	hash, err := util.NewFixedStringHash(srcIP.To16().String() + srcNUID.String() + dstIP.To16().String() + dstNUID.String())
	if err != nil {
		return nil, err
	}

	zeekUID, err := util.NewFixedStringHash(parseConn.UID)
	if err != nil {
		return nil, err
	}

	filtered := cfg.Filtering.FilterConnPair(srcIP, dstIP)

	entry := &ConnEntry{
		ImportTime:  importTime,
		ZeekUID:     zeekUID,
		Filtered:    filtered,
		Hash:        hash,
		Timestamp:   time.Unix(int64(parseConn.TimeStamp), 0),
		ImportID:    importID,
		Src:         srcIP,
		Dst:         dstIP,
		SrcNUID:     srcNUID,
		DstNUID:     dstNUID,
		SrcPort:     uint16(parseConn.SourcePort),
		DstPort:     uint16(parseConn.DestinationPort),
		ZeekHistory: parseConn.History,
		MissedBytes: parseConn.MissedBytes,
		Proto:       parseConn.Proto,
		Service:     parseConn.Service,
		Duration:    parseConn.Duration,
		SrcLocal:    cfg.Filtering.CheckIfInternal(srcIP),
		DstLocal:    cfg.Filtering.CheckIfInternal(dstIP),
		ICMPType:    icmpType,
		ICMPCode:    icmpCode,
		SrcBytes:    parseConn.OrigBytes,
		DstBytes:    parseConn.RespBytes,
		SrcIPBytes:  parseConn.OrigIPBytes,
		DstIPBytes:  parseConn.RespIPBytes,
		SrcPackets:  parseConn.OrigPackets,
		DstPackets:  parseConn.RespPackets,
		ConnState:   parseConn.ConnState,
	}

	// conn is treated differently than the rest of the logs since some other logs might need to correlate
	// the zeek_uid data for entries that would otherwise be filtered out;
	// For example: proxy connections require linking via zeek uid, but if the conn record is filtered out, then
	// it will never get populated
	// Filter out from never included list before adding it to the uconn map to allow blocking subnets
	// that could end up overcommitting memory
	ignore := cfg.Filtering.FilterConnPairForHTTP(srcIP, dstIP)
	if ignore {
		return nil, nil
	}

	return entry, nil
}

// writeUnfilteredConns copies connections from conn_tmp to conn that were not marked as being filtered
func (importer *Importer) writeUnfilteredConns(progress *tea.Program, open bool, spinnerID int) error {

	tmpTable := "conn_tmp"
	table := "conn"
	if open {
		tmpTable = "openconn_tmp"
		table = "openconn"
	}
	chCtx := importer.Database.QueryParameters(clickhouse.Parameters{
		"tmp_table": tmpTable,
		"table":     table,
	})

	err := importer.Database.Conn.Exec(chCtx, `
		INSERT INTO {table:Identifier} (
			import_time, import_id, zeek_uid, hash, ts, src, dst, src_nuid, dst_nuid,
			src_port, dst_port, missing_host_header, missing_host_useragent, proto, service,
			conn_state, duration, src_local, dst_local, icmp_type, icmp_code, src_bytes, dst_bytes,
			src_ip_bytes, dst_ip_bytes, src_packets, dst_packets, missed_bytes, zeek_history
		) SELECT import_time, import_id, zeek_uid, hash, ts, src, dst, src_nuid, dst_nuid,
			src_port, dst_port, missing_host_header, missing_host_useragent, proto, service,
			conn_state, duration, src_local, dst_local, icmp_type, icmp_code, src_bytes, dst_bytes,
			src_ip_bytes, dst_ip_bytes, src_packets, dst_packets, missed_bytes, zeek_history
		FROM {tmp_table:Identifier}
		WHERE filtered = false
	`)

	progress.Send(progressbar.ProgressSpinnerMsg(spinnerID))
	return err
}
