package importer

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/importer/zeektypes"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"

	"github.com/google/uuid"
)

var errMissingQuery = "blank or missing query field in dns log entry, skipping entry"

type DNSEntry struct {
	ImportTime          time.Time        `ch:"import_time"`
	ZeekUID             util.FixedString `ch:"zeek_uid"`
	Hash                util.FixedString `ch:"hash"`
	Timestamp           time.Time        `ch:"ts"`
	Src                 net.IP           `ch:"src"`
	Dst                 net.IP           `ch:"dst"`
	SrcNUID             uuid.UUID        `ch:"src_nuid"`
	DstNUID             uuid.UUID        `ch:"dst_nuid"`
	SrcPort             uint16           `ch:"src_port"`
	DstPort             uint16           `ch:"dst_port"`
	SrcLocal            bool             `ch:"src_local"`
	DstLocal            bool             `ch:"dst_local"`
	TransactionID       uint16           `ch:"transaction_id"`
	RoundTripTime       float64          `ch:"round_trip_time"`
	Query               string           `ch:"query"`
	QueryClassCode      uint16           `ch:"query_class_code"`
	QueryClassName      string           `ch:"query_class_name"`
	QueryTypeCode       uint16           `ch:"query_type_code"`
	QueryTypeName       string           `ch:"query_type_name"`
	ResponseCode        uint16           `ch:"response_code"`
	ResponseCodeName    string           `ch:"response_code_name"`
	AuthoritativeAnswer bool             `ch:"authoritative_answer"`
	RecursionDesired    bool             `ch:"recursion_desired"`
	RecursionAvailable  bool             `ch:"recursion_available"`
	Z                   uint16           `ch:"z"`
	Answers             []string         `ch:"answers"`
	TTLs                []float64        `ch:"ttls"`
	Rejected            bool             `ch:"rejected"`
	// PDNS field
	ResolvedIP net.IP `ch:"resolved_ip"`
}

type UniqueFQDN struct {
	Hash    util.FixedString `ch:"hash"`
	Src     net.IP           `ch:"src"`
	Dst     net.IP           `ch:"dst"`
	FQDN    string           `ch:"fqdn"`
	SrcNUID uuid.UUID        `ch:"src_nuid"`
	DstNUID uuid.UUID        `ch:"dst_nuid"`
}

// parseDNS listens on a channel of raw dns log records, formats them into dns and pdns entries and and sends them to be written to the database
func parseDNS(cfg *config.Config, dns <-chan zeektypes.DNS, dnsOutput, pdnsOutput chan<- database.Data, numDNS, numPDNSRaw *uint64, importTime time.Time) {
	logger := zlog.GetLogger()

	// loop over raw dns channel
	for d := range dns {

		// parse raw record as a dns entry
		entry, err := formatDNSRecord(cfg, &d, importTime)
		if err != nil {
			logger.Debug().Err(err).
				Str("log_path", d.LogPath).
				Str("zeek_uid", d.UID).
				Str("timestamp", (time.Unix(int64(d.TimeStamp), 0)).String()).
				Str("src", d.Source).
				Str("dst", d.Destination).
				Str("query", d.Query).
				Send()
			continue
		}

		// entry was subject to filtering
		if entry == nil {
			continue
		}

		dnsOutput <- entry // send to dns log writer

		// addToUDNS(uDNSMap, entry)   // add to unique dns map
		atomic.AddUint64(numDNS, 1) // increment dns record counter

		// parse dns entry into pdns entries based on dns entries's resolved ips
		parsePDNSRecord(entry, pdnsOutput, numPDNSRaw)

	}
}

// formatDNSRecord takes a raw dns record and formats it into the structure needed by the database
func formatDNSRecord(cfg *config.Config, parseDNS *zeektypes.DNS, importTime time.Time) (*DNSEntry, error) {

	// get source destination pair
	src := parseDNS.Source
	dst := parseDNS.Destination

	// parse addresses into binary format
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)

	// verify that both addresses were able to be parsed successfully
	if (srcIP == nil) || (dstIP == nil) {
		return nil, errors.New(errParseSrcDst)
	}

	// verify that query field is set
	if parseDNS.Query == "" {
		return nil, errors.New(errMissingQuery)
	}

	// ignore domains that have no periods (com, org, uk)
	if !strings.Contains(parseDNS.Query, ".") {
		return nil, nil
	}

	// Run query through filter to filter out certain domains and
	// filter out traffic which is external -> external or external -> internal (if specified in the config file)
	ignore := (cfg.Filter.FilterDomain(parseDNS.Query) || cfg.Filter.FilterDNSPair(srcIP, dstIP))

	// If domain is not subject to filtering, process
	if ignore {
		return nil, nil
	}

	srcNUID := util.ParseNetworkID(srcIP, parseDNS.AgentUUID)
	dstNUID := util.ParseNetworkID(dstIP, parseDNS.AgentUUID)

	zeekUID, err := util.NewFixedStringHash(parseDNS.UID)
	if err != nil {
		return nil, err
	}

	hash, err := util.NewFixedStringHash(srcIP.To16().String(), dstIP.To16().String(), parseDNS.Query)
	if err != nil {
		return nil, err
	}

	entry := &DNSEntry{
		ImportTime:          importTime,
		ZeekUID:             zeekUID,
		Hash:                hash,
		Timestamp:           time.Unix(int64(parseDNS.TimeStamp), 0),
		Src:                 srcIP,
		Dst:                 dstIP,
		SrcNUID:             srcNUID,
		DstNUID:             dstNUID,
		SrcPort:             uint16(parseDNS.SourcePort),
		DstPort:             uint16(parseDNS.DestinationPort),
		SrcLocal:            cfg.Filter.CheckIfInternal(srcIP),
		DstLocal:            cfg.Filter.CheckIfInternal(dstIP),
		TransactionID:       uint16(parseDNS.TransID),
		RoundTripTime:       parseDNS.RTT,
		Query:               parseDNS.Query,
		QueryClassCode:      uint16(parseDNS.QClass),
		QueryClassName:      parseDNS.QClassName,
		QueryTypeCode:       uint16(parseDNS.QType),
		QueryTypeName:       parseDNS.QTypeName,
		ResponseCode:        uint16(parseDNS.RCode),
		ResponseCodeName:    parseDNS.RCodeName,
		AuthoritativeAnswer: parseDNS.AA,
		RecursionDesired:    parseDNS.RD,
		RecursionAvailable:  parseDNS.RA,
		Z:                   uint16(parseDNS.Z),
		Answers:             parseDNS.Answers,
		TTLs:                parseDNS.TTLs,
		Rejected:            parseDNS.Rejected,
	}

	return entry, nil
}

// parsePDNSRecord takes a single dns entry and splits it into multiple entries, one for each answer with a resolved ip in the dns record.
func parsePDNSRecord(dnsRecord *DNSEntry, writeChan chan<- database.Data, numDNS *uint64) {

	uniqueResolvedMap := make(map[string]bool)

	if dnsRecord.QueryTypeName == "A" {
		// attempt to parse answers, copy the entry for every resolved IP

		// storing resolved IPs as an IPv6 column instead of an Array(IPv6) column significantly improves the
		// lookup time of resolved IPs
		for _, answer := range dnsRecord.Answers {
			answerIP := net.ParseIP(answer)
			// Check if answer is an IP address and store it if it is
			if answerIP != nil {
				uniqueResolvedMap[answer] = true
				// we must create a copy of this entry by dereferencing it before
				// assigning the resolved IP and sending it to the writer
				newEntry := *dnsRecord
				newEntry.ResolvedIP = answerIP.To16()
				writeChan <- &newEntry
				atomic.AddUint64(numDNS, 1) // increment pdns counter
			}
		}
	}
}
