package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/activecm/rita/v5/config"
	zlog "github.com/activecm/rita/v5/logger"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

var ErrInvalidDatabaseConnection = fmt.Errorf("database connection is nil")
var ErrInvalidMinMaxTimestamp = fmt.Errorf("invalid min or max timestamp")

// DB is the workhorse container for messing with the database
type DB struct {
	Conn            driver.Conn
	selected        string
	Rolling         bool
	rebuild         bool
	ctx             context.Context
	cancel          context.CancelFunc
	ImportStartedAt time.Time
}

// GetSelectedDB returns the name of the target database of db connection
func (db *DB) GetSelectedDB() string {
	return db.selected
}

// QueryParameters generates ClickHouse query parameters by creating a context with the specified parameters in it
func (db *DB) QueryParameters(params clickhouse.Parameters) context.Context {
	return clickhouse.Context(db.ctx, clickhouse.WithParameters(params))
}

// GetContext returns the context for the database connection
func (db *DB) GetContext() context.Context {
	return db.ctx
}

// getConn returns the driver connection
func (db *DB) getConn() driver.Conn {
	return db.Conn
}

func (db *DB) GetBeaconMinMaxTimestamps() (time.Time, time.Time, bool, error) {

	var minTS, maxTS time.Time
	var notFromConn bool

	if db.Conn == nil {
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, ErrInvalidDatabaseConnection
	}

	logger := zlog.GetLogger()

	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})
	// min timestamp: max timestamp - 24 hours, capped to the actual minimum timestamp from the logs
	// max timestamp: max timestamp in the logs
	err := db.Conn.QueryRow(ctx, `
		SELECT greatest(min_ts, timestamp_sub(HOUR, 24, max_ts)) as min_ts, max_ts FROM (
			SELECT min(min_ts) AS min_ts, max(max_ts) AS max_ts FROM metadatabase.min_max
			WHERE database = {database:String} AND beacon = true
			GROUP BY database
		)
	`).Scan(&minTS, &maxTS)

	// return error if the error is not a no rows found error
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Err(err).Str("database", db.selected).Msg("failed to get max ts from metadatabase min_max table")
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, err
	}

	if maxTS.IsZero() {
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, ErrInvalidMinMaxTimestamp
	}
	if minTS.IsZero() {
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, ErrInvalidMinMaxTimestamp
	}

	// if dataset is not rolling or if the max timestamp is over 24 hours ago, use the max timestamp
	return minTS, maxTS, notFromConn, nil

}

func (db *DB) GetTrueMinMaxTimestamps() (time.Time, time.Time, bool, bool, error) {
	logger := zlog.GetLogger()

	var minTS, maxTS time.Time
	var notFromConn bool
	var useCurrentTime bool

	if db.Conn == nil {
		return time.Unix(0, 0), time.Unix(0, 0), false, false, ErrInvalidDatabaseConnection
	}

	rolling, err := GetRollingStatus(db.GetContext(), db.Conn, db.GetSelectedDB())
	if err != nil && !errors.Is(err, ErrDatabaseNotFound) {
		return time.Unix(0, 0), time.Unix(0, 0), false, false, err
	}
	if errors.Is(err, ErrDatabaseNotFound) {
		rolling = db.Rolling
	}

	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})
	// min timestamp: max timestamp - 24 hours, capped to the actual minimum timestamp from the logs
	// max timestamp: max timestamp in the logs
	err = db.Conn.QueryRow(ctx, `
		SELECT greatest(min_ts, timestamp_sub(HOUR, 24, max_ts)) as min_ts, max_ts FROM (
			SELECT min(min_ts) AS min_ts, max(max_ts) AS max_ts FROM metadatabase.min_max
			WHERE database = {database:String} 
			GROUP BY database
		)
	`).Scan(&minTS, &maxTS)

	// return error if the error is not a no rows found error
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Err(err).Str("database", db.selected).Msg("failed to get max ts from metadatabase min_max table")
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, useCurrentTime, err
	}

	if maxTS.IsZero() {
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, useCurrentTime, fmt.Errorf("could not find any viable max timestamp")
	}
	if minTS.IsZero() {
		return time.Unix(0, 0), time.Unix(0, 0), notFromConn, useCurrentTime, fmt.Errorf("could not find any viable min timestamp")
	}

	// if dataset is rolling and the max timestamp is not over 24 hours ago, use the current time for first seen
	if rolling && time.Since(maxTS).Hours() <= 24 {
		useCurrentTime = true
	}

	// if dataset is not rolling or if the max timestamp is over 24 hours ago, use the max timestamp
	return minTS, maxTS, notFromConn, useCurrentTime, nil

}

// GetNetworkSize returns the number of distinct internal hosts for the past 24 hours, which is used to determine prevalence
func (db *DB) GetNetworkSize(minTS time.Time) (uint64, error) {
	logger := zlog.GetLogger()

	var networkSize uint64

	ctx := db.QueryParameters(clickhouse.Parameters{
		"min_ts": fmt.Sprintf("%d", minTS.UTC().Unix()),
	})

	err := db.Conn.QueryRow(ctx, `
		SELECT count() FROM (
			-- uconn
			SELECT DISTINCT src FROM uconn
			WHERE src_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT dst AS src FROM uconn
			WHERE dst_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			-- openconn
			SELECT DISTINCT src FROM openconn
			WHERE src_local = true
			UNION DISTINCT
			SELECT DISTINCT dst AS src FROM openconn
			WHERE dst_local = true
			UNION DISTINCT
			-- http
			SELECT DISTINCT src FROM usni
			WHERE http = true AND src_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT dst AS src FROM usni
			WHERE http = true AND dst_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			-- openhttp
			SELECT DISTINCT src FROM openhttp
			WHERE src_local = true
			UNION DISTINCT
			SELECT DISTINCT dst AS src FROM openhttp
			WHERE dst_local = true
			UNION DISTINCT
			-- dns
			SELECT DISTINCT src FROM udns
			WHERE src_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
			UNION DISTINCT
			SELECT DISTINCT dst AS src FROM udns
			WHERE dst_local = true AND hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
		)
	`).Scan(&networkSize)

	if err != nil {
		logger.Err(err).Str("database", db.selected).Msg("failed to network size from uconn table")
		return networkSize, err
	}

	return networkSize, nil
}

// TruncateTmpLinkTables truncates the tables that are used to link zeek uids.
// This should be called after each import so that these tmp tables don't take up unnecessary disk space.
func (db *DB) TruncateTmpLinkTables() error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.conn_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.ssl_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.http_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openconn_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openssl_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openhttp_tmp
	`); err != nil {
		return err
	}
	return nil
}

// ResetTemporaryTables clears out data in tmp tables (if they exist) from the previous import
func (db *DB) ResetTemporaryTables() error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
	})

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openconn
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openhttp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openssl
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.uconn_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.openconnhash_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.opensniconn_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.sniconn_tmp
	`); err != nil {
		return err
	}

	if err := db.Conn.Exec(ctx, `--sql
		TRUNCATE TABLE IF EXISTS {database:Identifier}.dns_tmp
	`); err != nil {
		return err
	}

	return db.TruncateTmpLinkTables()

}

// ConnectToDB sets up a new connection to the specified database
func ConnectToDB(ctx context.Context, db string, cfg *config.Config, cancel context.CancelFunc) (*DB, error) {
	// connect to the database
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.Env.DBConnection},
		Auth: clickhouse.Auth{
			Database: db,
			Username: cfg.Env.DBUsername,
			Password: cfg.Env.DBPassword,
		},
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			// dialCount++
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		Debug: false,
		Debugf: func(format string, v ...any) {
			log.Println(format, v)
		},
		Settings: clickhouse.Settings{
			"max_execution_time": cfg.RITA.MaxQueryExecutionTime,
			"mutations_sync":     1,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:          time.Second * 120,
		MaxOpenConns:         50,
		MaxIdleConns:         50,
		ConnMaxLifetime:      time.Duration(1) * time.Hour,
		ConnOpenStrategy:     clickhouse.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 10240,

		ClientInfo: clickhouse.ClientInfo{ // optional, please see Client info section in the clickhouse-go README.md
			Products: []struct {
				Name    string
				Version string
			}{
				{Name: "rita", Version: "0.1"},
			},
		},
	})

	// check if the connection call had any errors
	if err != nil {
		return nil, err
	}

	// check if the connection is valid
	if err := conn.Ping(ctx); err != nil {
		// if exception, ok := err.(*clickhouse.Exception); ok {
		// 	fmt.Printf("Exception [%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		// }
		return nil, err
	}

	// fmt.Println("Validated connection to database", db)

	return &DB{
		Conn:     conn,
		ctx:      ctx,
		cancel:   cancel,
		selected: db,
	}, nil
}

// GetFirstSeenTimestamp gets the relative timestamp to use for calculating/displaying first seen.
// Returns max timestamp, whether or not to use the current time, and error
// func (db *DB) GetFirstSeenTimestamp() (time.Time, time.Time, bool, error) {
// 	rolling, err := GetRollingStatus(db.GetContext(), db.Conn, db.GetSelectedDB())
// 	if err != nil {
// 		return time.Unix(0, 0), time.Unix(0, 0), false, err
// 	}

// 	minTS, maxTS, _, err := db.GetMinMaxTimestamps()
// 	if err != nil {
// 		return time.Unix(0, 0), time.Unix(0, 0), false, fmt.Errorf("could not get min/max timestamps for analysis: %w", err)
// 	}

// 	// if dataset is not rolling or if the max timestamp is over 24 hours ago, use the max timestamp
// 	if !rolling || time.Since(maxTS).Hours() > 24 {
// 		return maxTS, minTS, false, nil
// 	}

// 	// if rolling and maxTS <= 24 hrs ago, use the current time
// 	return time.Unix(0, 0), time.Unix(0, 0), true, nil
// }
