package importer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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

var errServerNameEmpty = errors.New("server name is blank")

type SSLEntry struct {
	ImportTime       time.Time        `ch:"import_time"`
	ZeekUID          util.FixedString `ch:"zeek_uid"`
	Hash             util.FixedString `ch:"hash"`
	Timestamp        time.Time        `ch:"ts"`
	Src              net.IP           `ch:"src"`
	Dst              net.IP           `ch:"dst"`
	SrcNUID          uuid.UUID        `ch:"src_nuid"`
	DstNUID          uuid.UUID        `ch:"dst_nuid"`
	SrcPort          uint16           `ch:"src_port"`
	DstPort          uint16           `ch:"dst_port"`
	Duration         float64          `ch:"duration"`
	SrcLocal         bool             `ch:"src_local"`
	DstLocal         bool             `ch:"dst_local"`
	SrcBytes         int64            `ch:"src_bytes"`
	DstBytes         int64            `ch:"dst_bytes"`
	SrcIPBytes       int64            `ch:"src_ip_bytes"`
	DstIPBytes       int64            `ch:"dst_ip_bytes"`
	SrcPackets       int64            `ch:"src_packets"`
	DstPackets       int64            `ch:"dst_packets"`
	Proto            string           `ch:"proto"`
	Service          string           `ch:"service"`
	ConnState        string           `ch:"conn_state"`
	Version          string           `ch:"version"`
	Cipher           string           `ch:"cipher"`
	Curve            string           `ch:"curve"`
	ServerName       string           `ch:"server_name"`
	Resumed          bool             `ch:"resumed"`
	NextProtocol     string           `ch:"next_protocol"`
	Established      bool             `ch:"established"`
	ServerCertFUIDs  []string         `ch:"server_cert_fuids"`
	ClientCertFUIDs  []string         `ch:"client_cert_fuids"`
	ServerSubject    string           `ch:"server_subject"`
	ServerIssuer     string           `ch:"server_issuer"`
	ClientSubject    string           `ch:"client_subject"`
	ClientIssuer     string           `ch:"client_issuer"`
	ValidationStatus string           `ch:"validation_status"`
	JA3              string           `ch:"ja3"`
	JA3S             string           `ch:"ja3s"`
}

// parseSSL listens on a channel of raw ssl/openssl log records, formats them and sends them to be linked with conn/openconn records and written to the database
// func parseSSL(ssl <-chan zeektypes.SSL, zeekUIDMap cmap.ConcurrentMap[string, *ZeekUIDRecord], uSSLMap cmap.ConcurrentMap[string, *UniqueFQDN], output chan database.Data, numSSL *uint64) {
func parseSSL(ssl <-chan zeektypes.SSL, output chan database.Data, importTime time.Time, numSSL *uint64) {
	// logger := zlog.GetLogger()

	// loop over raw ssl/openssl channel
	for s := range ssl {

		// parse raw record record as an ssl/openssl entry
		entry, err := formatSSLRecord(&s, importTime)
		if err != nil {
			// logger.Warn().Err(err).
			// 	Str("log_path", s.LogPath).
			// 	Str("zeek_uid", s.UID).
			// 	Str("timestamp", (time.Unix(int64(s.TimeStamp), 0)).String()).
			// 	Str("src", s.Source).
			// 	Str("dst", s.Destination).
			// 	Str("sni", s.ServerName).
			// 	Send()
			continue
		}

		// entry was subject to filtering
		if entry == nil {
			continue
		}

		output <- entry
		// increment record counter
		atomic.AddUint64(numSSL, 1)
	}
}

// formatSSLRecord takes a raw ssl record and formats it into the structure needed by the database
func formatSSLRecord(parseSSL *zeektypes.SSL, importTime time.Time) (*SSLEntry, error) {
	// logger := zerolog.GetLogger()
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	// get source destination pair
	src := parseSSL.Source
	dst := parseSSL.Destination

	// parse source and destination
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)

	// verify that both addresses were parsed successfully
	if (srcIP == nil) || (dstIP == nil) {
		return nil, errors.New(errParseSrcDst)
	}

	// get sni
	sni := parseSSL.ServerName

	if sni == "" {
		// logger.Debug().
		// 	Str("log_path", parseSSL.LogPath).
		// 	Str("zeek_uid", parseSSL.UID).
		// 	Str("timestamp", (time.Unix(int64(parseSSL.TimeStamp), 0)).String()).
		// 	Str("src", parseSSL.Source).
		// 	Str("dst", parseSSL.Destination).
		// 	Str("sni", parseSSL.ServerName).
		// 	Msg("sni field is empty")
		return nil, fmt.Errorf("could not parse SSL connection %s -> %s: %w", src, dst, errServerNameEmpty)
	}

	ignore := cfg.Filter.FilterDomain(sni) || cfg.Filter.FilterConnPair(srcIP, dstIP) || cfg.Filter.FilterSNIPair(srcIP)
	if ignore {
		return nil, nil
	}

	srcNUID := util.ParseNetworkID(srcIP, parseSSL.AgentUUID)
	dstNUID := util.ParseNetworkID(dstIP, parseSSL.AgentUUID)

	zeekUID, err := util.NewFixedStringHash(parseSSL.UID)
	if err != nil {
		return nil, err
	}

	hash, err := util.NewFixedStringHash(srcIP.To16().String(), srcNUID.String(), dstIP.To16().String(), dstNUID.String(), sni)
	if err != nil {
		return nil, err
	}

	entry := &SSLEntry{
		ImportTime:       importTime,
		ZeekUID:          zeekUID,
		Hash:             hash,
		Timestamp:        time.Unix(int64(parseSSL.TimeStamp), 0),
		Src:              srcIP,
		Dst:              dstIP,
		SrcNUID:          srcNUID,
		DstNUID:          dstNUID,
		SrcPort:          uint16(parseSSL.SourcePort),
		DstPort:          uint16(parseSSL.DestinationPort),
		SrcLocal:         cfg.Filter.CheckIfInternal(srcIP),
		DstLocal:         cfg.Filter.CheckIfInternal(dstIP),
		Version:          parseSSL.Version,
		Cipher:           parseSSL.Cipher,
		Curve:            parseSSL.Curve,
		ServerName:       parseSSL.ServerName,
		Resumed:          parseSSL.Resumed,
		NextProtocol:     parseSSL.NextProtocol,
		Established:      parseSSL.Established,
		ServerCertFUIDs:  parseSSL.CertChainFuids,
		ClientCertFUIDs:  parseSSL.ClientCertChainFuids,
		ServerSubject:    parseSSL.Subject,
		ServerIssuer:     parseSSL.Issuer,
		ClientSubject:    parseSSL.ClientSubject,
		ClientIssuer:     parseSSL.ClientIssuer,
		ValidationStatus: parseSSL.ValidationStatus,
		JA3:              parseSSL.JA3,
		JA3S:             parseSSL.JA3S,
	}

	return entry, nil
}

func (importer *Importer) writeLinkedSSL(ctx context.Context, progress *tea.Program, barID int, sslWriter *database.BulkWriter, open bool) error { //httpWriter chan database.Data, connWriter chan database.Data
	logger := logger.GetLogger()

	var totalSSL uint64
	err := importer.Database.Conn.QueryRow(importer.Database.GetContext(), `
		SELECT count() FROM ssl_tmp
	`).Scan(&totalSSL)
	if err != nil {
		return err
	}

	tmpTable := "ssl_tmp"
	tableB := "conn_tmp"
	if open {
		tmpTable = "openssl_tmp"
		tableB = "openconn_tmp"
	}

	chCtx := importer.Database.QueryParameters(clickhouse.Parameters{
		"tmp_table": tmpTable,
		"table_b":   tableB,
	})

	rows, err := importer.Database.Conn.Query(chCtx, `
	SELECT 
		s.zeek_uid as zeek_uid, c.ts AS ts, s.src as src, s.src_nuid as src_nuid, s.dst as dst, s.dst_nuid as dst_nuid,
		s.src_port as src_port, s.dst_port as dst_port, s.src_local as src_local, s.dst_local as dst_local, server_name as server_name,
		s.version as version, s.cipher as cipher, s.curve as curve, s.resumed as resumed, s.next_protocol as next_protocol, s.established as established, 
		s.server_cert_fuids as server_cert_fuids, client_cert_fuids, server_subject, server_issuer, client_subject, client_issuer, validation_status,
		ja3, ja3s,
		-- set proto and service regardless of whether it was linked already or not
		-- since multi-requests can use different dst ports and still have the same UID, so
		-- it is useful to be able to see the dst ports coming from multi request entries as well
		c.proto as proto, c.service as service,
		c.src_ip_bytes as src_ip_bytes,
		c.dst_ip_bytes as dst_ip_bytes,
		c.src_bytes as src_bytes,
		c.dst_bytes as dst_bytes,
		c.duration as duration,
		c.conn_state as conn_state,
		c.src_packets as src_packets,
		c.dst_packets as dst_packets
	FROM {tmp_table:Identifier} s
	INNER JOIN {table_b:Identifier} c USING zeek_uid
    
`)
	if err != nil {
		log.Panicln(err)
	}

	i := 0
	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling SSL connection linking")
			rows.Close()
			return ctx.Err()
		default:
			var entry SSLEntry

			err := rows.ScanStruct(&entry)
			if err != nil {
				log.Panicln(err)
			}
			i++
			if i%1000 == 0 {
				progress.Send(progressbar.ProgressMsg{ID: barID, Percent: float64(float64(i) / float64(totalSSL))})
			}
			entry.ImportTime = importer.Database.ImportStartedAt

			hash, err := util.NewFixedStringHash(entry.Src.To16().String(), entry.SrcNUID.String(), entry.ServerName)
			if err != nil {
				log.Panicln(err)
			}

			entry.Hash = hash
			sslWriter.WriteChannel <- &entry
		}
	}
	rows.Close()
	progress.Send(progressbar.ProgressMsg{ID: barID, Percent: 1})

	return nil
}
