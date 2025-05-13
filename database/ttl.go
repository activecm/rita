package database

import (
	"fmt"
	"strconv"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

// Check the status of a table's TTL:
// SELECT
// 	delete_ttl_info_min,
// 	delete_ttl_info_max
// FROM system.parts
// WHERE database='chickenstrip' and table = 'conn'

var LogTableTTLs = []string{"conn", "http", "ssl", "dns", "pdns_raw"}
var LogTableViewsHourTTLs = []string{"usni", "udns", "uconn", "mime_type_uris"}
var LogTableViewsDayTTLs = []string{"pdns"}
var AnalysisSnapshotHourTTLs = []string{"big_ol_histogram", "tls_proto", "http_proto", "exploded_dns", "rare_signatures", "port_info"}
var AnalysisSnapshotAnalyzedAtTTLs = []string{"threat_mixtape"}
var MetaDatabaseTTLs = []string{"historical_first_seen", "files"}
var MetaDatabaseYearTTLS = []string{"imports"}
var ZoneTransferTTLs = []string{"performed_zone_transfers", "zone_transfer"}

func (db *DB) createLogTableTTLs() error {
	if !db.Rolling {
		return fmt.Errorf("cannot create TTLs on non-rolling database: %s", db.selected)
	}
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	err := db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.conn MODIFY TTL import_time + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.http MODIFY TTL import_time + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.ssl MODIFY TTL import_time + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.dns MODIFY TTL import_time + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.pdns_raw MODIFY TTL import_time + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	// tables populated by materialized views [ TTL on import_hour ]
	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.usni MODIFY TTL import_hour + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.udns MODIFY TTL import_hour + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.uconn MODIFY TTL import_hour + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.pdns MODIFY TTL import_day + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.mime_type_uris MODIFY TTL import_hour + INTERVAL 26 HOURS`)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createSnapshotTableTTLs() error {
	if !db.Rolling {
		return fmt.Errorf("cannot create 'snapshot' TTLs on non-rolling database: %s", db.selected)
	}
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	err := db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.big_ol_histogram MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.tls_proto MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.http_proto MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.exploded_dns MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.rare_signatures MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.port_info MODIFY TTL import_hour + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	err = db.Conn.Exec(ctx, `--sql
		ALTER TABLE {database:Identifier}.threat_mixtape MODIFY TTL toDateTime(analyzed_at) + INTERVAL 2 WEEKS`)
	if err != nil {
		return err
	}

	return nil
}

func (server *ServerConn) createMetaDatabaseTTLs(monthsToKeepHistoricalFirstSeen int) error {
	ctx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{
		"days": strconv.Itoa(monthsToKeepHistoricalFirstSeen * 30),
	}))

	err := server.Conn.Exec(ctx, `--sql
		ALTER TABLE metadatabase.historical_first_seen MODIFY TTL last_seen + toIntervalDay({days:Int32})`)
	if err != nil {
		return err
	}

	err = server.Conn.Exec(ctx, `--sql
		ALTER TABLE metadatabase.files MODIFY TTL ts + INTERVAL 180 DAYS DELETE WHERE rolling = true`)
	if err != nil {
		return err
	}

	// DO NOT SET TTL ON ended_at, WILL BREAK
	err = server.Conn.Exec(ctx, `--sql
		ALTER TABLE metadatabase.imports MODIFY TTL toDateTime(started_at) + INTERVAL 1 YEAR`)
	if err != nil {
		return err
	}

	err = server.Conn.Exec(ctx, `--sql
		ALTER TABLE metadatabase.performed_zone_transfers MODIFY TTL performed_at + INTERVAL 90 DAYS`)
	if err != nil {
		return err
	}

	err = server.Conn.Exec(ctx, `--sql
		ALTER TABLE metadatabase.zone_transfer MODIFY TTL performed_at + INTERVAL 90 DAYS`)
	if err != nil {
		return err
	}

	return nil
}
