package zonetransfer

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/logger"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

var ErrDomainNotConfigured = errors.New("domain name or name server has not been configured for zone transfer")
var ErrZoneTransferNotEnabled = errors.New("zone transfers are not enabled for RITA")

type Record struct {
	PerformedAt time.Time `ch:"performed_at"`
	Hostname    string    `ch:"hostname"`
	IP          net.IP    `ch:"ip"`
	TTL         uint32    `ch:"ttl"`
	// domain forest info
	DomainName string `ch:"domain_name"`
	NameServer string `ch:"name_server"`
}

type PerformedZoneTransfer struct {
	PerformedAt time.Time `ch:"performed_at"`
	DomainName  string    `ch:"domain_name"`
	NameServer  string    `ch:"name_server"`
	Serial      uint32    `ch:"serial_soa"`
	MBox        string    `ch:"mbox"`
	IsIXFR      bool      `ch:"is_ixfr"`
}

type ZoneTransferConnectivityErrors struct {
	NameServerUnreachableUDPError error `json:"name_server_unreachable_udp"`
	NameServerUnreachableTCPError error `json:"name_server_unreachable_tcp"`
	UDPQueryFailedError           error `json:"udp_query_failed"`
	AXFRFailedError               error `json:"axfr_failed"`
}

type ZoneTransfer struct {
	domainName  string
	nameServer  string
	latestSOA   dns.SOA
	db          *database.ServerConn
	cfg         *config.Config
	performedAt time.Time
}

// NewZoneTransfer creates the struct needed for handling zone transfers
func NewZoneTransfer(db *database.ServerConn, cfg *config.Config) (*ZoneTransfer, error) {
	if len(cfg.ZoneTransfer.DomainName) == 0 || len(cfg.ZoneTransfer.NameServer) == 0 {
		return nil, ErrDomainNotConfigured
	}
	if db == nil {
		return nil, database.ErrInvalidDatabaseConnection
	}
	if err := db.CreateServerDBTables(); err != nil {
		return nil, fmt.Errorf("unable to setup system for zone transfers, err: %w", err)
	}
	return &ZoneTransfer{
		domainName:  cfg.ZoneTransfer.DomainName,
		nameServer:  cfg.ZoneTransfer.NameServer,
		db:          db,
		cfg:         cfg,
		performedAt: time.Now().UTC(),
	}, nil
}

// DoZT handles a zone transfer
func (zt *ZoneTransfer) DoZT(axfr bool) error {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	if axfr {
		// Set up an AXFR if requested
		m.SetAxfr(zt.domainName)
	} else {
		// Otherwise, set up an IXFR, using the domain name and latest SOA Serial and Mbox values
		m.SetIxfr(zt.domainName, zt.latestSOA.Serial, zt.domainName, zt.latestSOA.Mbox)
	}

	// create a channel for the dns "envelope"
	ch, err := t.In(m, zt.nameServer)

	if err != nil {
		return err
	}

	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)

	// create a writer for the zone_transfer table
	writer := database.NewBulkWriter(zt.db, zt.cfg, 1, "metadatabase.zone_transfer", "zone_transfer", "INSERT INTO metadatabase.zone_transfer", limiter, false)
	writer.Start(0)

	// since there could be a large volume of records coming in for a large domain, these records should be streamed via the dns envelope
	// and then written into batches as the results come in
	for env := range ch {
		if env.Error != nil {
			err = env.Error
			break
		}

		// Type switch to handle the DNS envelope types we care about (SOA for IXFR info, A and AAAA for mapping)
		for _, rr := range env.RR {
			// create record with standard metadata
			record := Record{PerformedAt: zt.performedAt, DomainName: zt.domainName, NameServer: zt.nameServer}

			switch rec := rr.(type) {
			case *dns.SOA:
				// contains the serial and mbox info to store
				zt.latestSOA = *rec
			case *dns.A:
				record.Hostname = strings.TrimSuffix(rec.Header().Name, ".")
				record.IP = rec.A
				record.TTL = rec.Header().Ttl
				writer.WriteChannel <- &record
			case *dns.AAAA:
				record.Hostname = strings.TrimSuffix(rec.Header().Name, ".")
				record.IP = rec.AAAA
				record.TTL = rec.Header().Ttl
				writer.WriteChannel <- &record
			}
		}
	}

	if err != nil {
		return err
	}

	writer.Close()

	// record that a zone transfer occurred
	zt.RecordZoneTransferPerformed()

	return nil
}

// RecordZoneTransferPerformed marks a completed zone transfer in the metadatabase and stores the most recent serial (SOA) found in the dns query
func (zt *ZoneTransfer) RecordZoneTransferPerformed() error {
	chCtx := zt.db.QueryParameters(clickhouse.Parameters{
		"performed_at": zt.performedAt.Format("2006-01-02 15:04:05"),
		"domain_name":  zt.domainName,
		"name_server":  zt.nameServer,
		"serial_soa":   strconv.FormatUint(uint64(zt.latestSOA.Serial), 10),
		"mbox":         zt.latestSOA.Mbox,
	})
	if err := zt.db.Conn.Exec(chCtx, `
		INSERT INTO metadatabase.performed_zone_transfers (performed_at, domain_name, name_server, serial_soa, mbox) 
		VALUES ( toDateTime({performed_at:String}, 'UTC'), {domain_name:String}, {name_server:String}, {serial_soa:UInt32}, {mbox:String} )
`); err != nil {
		return err
	}
	return nil
}

// FindLastZoneTransfer finds the last zone transfer that was performed for this zt's domain and name server
func (zt *ZoneTransfer) FindLastZoneTransfer() (*PerformedZoneTransfer, error) {
	chCtx := zt.db.QueryParameters(clickhouse.Parameters{
		"domain_name": zt.domainName,
		"name_server": zt.nameServer,
	})

	var lastZoneTransfer PerformedZoneTransfer
	if err := zt.db.Conn.QueryRow(chCtx, `
		SELECT max(performed_at) AS performed_at, domain_name, name_server, serial_soa, mbox, is_ixfr
		FROM metadatabase.performed_zone_transfers
		WHERE domain_name = {domain_name:String} AND name_server = {name_server:String}
		GROUP BY domain_name, name_server, serial_soa, mbox, is_ixfr
`).ScanStruct(&lastZoneTransfer); err != nil {
		// return nil PerformedZoneTransfer with no error if no zone transfer was found (ignore error)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &lastZoneTransfer, nil
}

// PerformZoneTransfer performs either an AXFR or IXFR zone transfer
func (zt *ZoneTransfer) PerformZoneTransfer() error {
	// skip if zone transfers are not enabled
	if !zt.cfg.ZoneTransfer.Enabled {
		return ErrZoneTransferNotEnabled
	}

	/*  ==== ZONE TRANSFERS ====
	AXFR zone transfers do a transfer of the entire domain,

	IXFR zone transfers do incremental zone transfers. They update the portions of the domain that have updated since the
	Serial (SOA) that was provided with the transfer request. For example, on Monday a zone transfer was performed and we noted that
	the current Serial is 100. On Tuesday, we perform an IXFR zone transfer and pass the Serial of 100 with the request. We will only
	get back the results that have changed since Monday instead of the entire domain forest.

	Performed zone transfers are stored in metadatabase.performed_zone_transfers, which tracks when a zone transfer was performed on a domain/name server and
	what the latest Serial was at the time. If no results match in performed_zone_transfers, then we do an AXFR transfer.
	*/

	// Try to find last zone transfer that was performed for this domain & name server
	lastZoneTransfer, err := zt.FindLastZoneTransfer()
	if err != nil {
		return fmt.Errorf("unable to find last performed zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
	}

	zlog := logger.GetLogger()

	transferType := "AXFR"
	// There was a match in performed_zone_transfers, do an IXFR transfer
	if lastZoneTransfer != nil {
		// Do an IXFR
		transferType = "IXFR"
		if err := zt.DoZT(false); err != nil {
			return fmt.Errorf("unable to perform IXFR zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
		}
	} else {
		// No match, do an AXFR
		if err := zt.DoZT(true); err != nil {
			return fmt.Errorf("unable to perform AXFR zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
		}
	}
	zlog.Info().Str("domain", zt.domainName).Str("name_server", zt.nameServer).Uint32("lastest_soa", zt.latestSOA.Serial).Msg(fmt.Sprintf("Successfully performed %s zone transfer", transferType))

	return nil
}

func (zt *ZoneTransfer) TestNetConnectivity(protocol string) error {
	conn, err := net.DialTimeout(protocol, zt.cfg.ZoneTransfer.NameServer, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (zt *ZoneTransfer) TestConnectivity() ZoneTransferConnectivityErrors {

	var result ZoneTransferConnectivityErrors

	zlog := logger.GetLogger()

	if err := zt.TestNetConnectivity("udp"); err != nil {
		result.NameServerUnreachableUDPError = err
		zlog.Error().Err(err).Str("name_server", zt.nameServer).Msg("name server unreachable via UDP")
	}

	if err := zt.TestNetConnectivity("tcp"); err != nil {
		result.NameServerUnreachableTCPError = err
		zlog.Error().Err(err).Str("name_server", zt.nameServer).Msg("name server unreachable via TCP")
	}

	client := new(dns.Client)
	client.Net = "udp"
	msg := new(dns.Msg)
	msg.SetQuestion(zt.domainName, dns.TypeSOA)

	_, _, err := client.Exchange(msg, zt.nameServer)
	if err != nil {
		result.UDPQueryFailedError = err
		zlog.Error().Err(err).Str("name_server", zt.nameServer).Str("domain_name", zt.domainName).Msg("failed to perform SOA query over UDP")
	}

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(zt.domainName)

	_, err = t.In(m, zt.nameServer)
	if err != nil {
		result.AXFRFailedError = err
		zlog.Error().Err(err).Str("name_server", zt.nameServer).Str("domain_name", zt.domainName).Msg("failed to perform AXFR zone transfer")
	}

	zlog.Info().Str("name_server", zt.nameServer).Str("domain_name", zt.domainName).Msg("connectivity check to domain for zone transfers was successful")

	return result
}

// for testing
func (zt *ZoneTransfer) SetTransferInfo(transferInfo PerformedZoneTransfer) {
	zt.performedAt = transferInfo.PerformedAt
	zt.domainName = transferInfo.DomainName
	zt.nameServer = transferInfo.NameServer
	zt.latestSOA.Serial = transferInfo.Serial
	zt.latestSOA.Mbox = transferInfo.MBox
}
