package zonetransfer

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
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

type ZoneTransfer struct {
	domainName  string
	nameServer  string
	latestSOA   dns.SOA
	records     map[string][]Record
	db          *database.ServerConn
	cfg         *config.Config
	performedAt time.Time
	isIXFR      bool
}

func NewZoneTransfer(db *database.ServerConn, cfg *config.Config) (*ZoneTransfer, error) {
	if len(cfg.ZoneTransfer.DomainName) == 0 || len(cfg.ZoneTransfer.NameServer) == 0 {
		return nil, ErrDomainNotConfigured
	}
	if db == nil {
		return nil, database.ErrInvalidDatabaseConnection
	}
	return &ZoneTransfer{
		domainName:  cfg.ZoneTransfer.DomainName,
		nameServer:  cfg.ZoneTransfer.NameServer,
		records:     make(map[string][]Record),
		db:          db,
		cfg:         cfg,
		performedAt: time.Now().UTC(),
	}, nil
}

// NOTE: we might not need this, still planning
// GetCurrentSerial gets the current authoritative serial of the domain.
// This should be called before performing the zone transfer so that we can write it out with
// the current results
func (zt *ZoneTransfer) GetCurrentSerial() error {

	m := new(dns.Msg)
	m.SetQuestion(zt.domainName, dns.TypeSOA)
	m.RecursionDesired = false

	c := new(dns.Client)
	r, _, err := c.Exchange(m, zt.nameServer)
	if err != nil {
		return err
	}

	for _, ans := range r.Answer {
		if r.Authoritative {
			if soa, ok := ans.(*dns.SOA); ok {
				fmt.Println("SOA Serial:", soa.Serial)
				fmt.Println("SOA MBox:", soa.Mbox)
				fmt.Println("Primary NS:", soa.Ns)
			}
		}
	}
	return nil
}

func (zt *ZoneTransfer) DoZT(axfr bool) error {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	if axfr {
		// Set up an AXFR if we want to
		m.SetAxfr(zt.domainName)
	} else {
		// Otherwise, set up an IXFR, using the domain name and latest SOA Serial and Mbox values
		m.SetIxfr(zt.domainName, zt.latestSOA.Serial, zt.domainName, zt.latestSOA.Mbox)
	}
	ch, err := t.In(m, zt.nameServer)

	if err != nil {
		return err
	}

	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)
	writer := database.NewBulkWriter(zt.db, zt.cfg, 1, "metadatabase.zone_transfer", "zone_transfer", "INSERT INTO metadatabase.zone_transfer", limiter, false)
	writer.Start(0)
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
				zt.latestSOA = *rec
			case *dns.A:
				record.Hostname = strings.TrimSuffix(rec.Header().Name, ".")
				record.IP = rec.A
				record.TTL = rec.Header().Ttl
				zt.records[rec.A.String()] = append(zt.records[rec.A.String()], record)
				writer.WriteChannel <- &record
			case *dns.AAAA:
				record.Hostname = strings.TrimSuffix(rec.Header().Name, ".")
				zt.records[rec.AAAA.String()] = append(zt.records[rec.AAAA.String()], record)
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

	zt.recordZoneTransferPerformed()

	// Sort the record slices (currently by TTL just for funsies, but if we store timestamp information we will likely want to use that field as well)
	for _, result := range zt.records {
		sort.Slice(result, func(i, j int) bool {
			return result[i].TTL > result[j].TTL
		})
	}

	return nil
}

// recordZoneTransferPerformed marks a completed zone transfer in the metadatabase and stores the most recent serial (SOA) found in the dns query
func (zt ZoneTransfer) recordZoneTransferPerformed() error {
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

func (zt ZoneTransfer) FindLastZoneTransfer() (*PerformedZoneTransfer, error) {
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

// Return the record map structure as a string
func (zt ZoneTransfer) String() string {
	ret := ""
	for key, result := range zt.records {
		ret += fmt.Sprintf("%s %v\n", key, result)
	}
	return ret
}

func (zt ZoneTransfer) PerformZoneTransfer() error {
	// Try to find last zone transfer that was performed for this domain & name server
	lastZoneTransfer, err := zt.FindLastZoneTransfer()
	if err != nil {
		return fmt.Errorf("unable to find last performed zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
	}

	zlog := logger.GetLogger()

	transferType := "AXFR"
	if lastZoneTransfer != nil {
		// Do an IXFR
		transferType = "IXFR"
		if err := zt.DoZT(false); err != nil {
			return fmt.Errorf("unable to perform IXFR zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
		}
	} else {
		// Do an AXFR
		if err := zt.DoZT(true); err != nil {
			return fmt.Errorf("unable to perform AXFR zone transfer on domain '%s' via name server '%s': %w", zt.domainName, zt.nameServer, err)
		}
	}
	zlog.Info().Str("domain", zt.domainName).Str("name_server", zt.nameServer).Uint32("lastest_soa", zt.latestSOA.Serial).Msg(fmt.Sprintf("Successfully performed %s zone transfer", transferType))

	return nil
}
