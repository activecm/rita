package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/activecm/rita/v5/config"
	zlog "github.com/activecm/rita/v5/logger"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/spf13/afero"
)

type ServerConn struct {
	Conn   driver.Conn
	addr   string
	ctx    context.Context
	cancel context.CancelFunc
}

var ErrNoMetaDBImportRecordForDatabase = errors.New("no import record found for database")
var ErrDatabaseNotFound = errors.New("database does not exist")
var ErrDatabaseNameEmpty = errors.New("database name cannot be empty")
var ErrMissingConfig = errors.New("config cannot be nil")
var ErrImportTwiceNonRolling = errors.New("cannot import more than once to a non-rolling database")
var errRollingStatusFailure = errors.New("failed to detect rolling status of given import database")
var errRollingFlagMissing = errors.New("cannot import non-rolling data to a rolling database")

// SetUpNewImport creates the database requested for this import and returns a new DB struct for connection to said database
func SetUpNewImport(afs afero.Fs, cfg *config.Config, dbName string, rollingFlag bool, rebuildFlag bool) (*DB, error) {
	logger := zlog.GetLogger()

	// validate parameters
	if cfg == nil {
		return nil, ErrMissingConfig
	}

	if dbName == "" {
		return nil, ErrDatabaseNameEmpty
	}

	ctx := context.Background()

	// connect to ClickHouse server
	server, err := ConnectToServer(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// set up metadatabase if it does not exist yet
	err = server.CreateServerDBTables()
	if err != nil {
		return nil, err
	}

	err = server.createMetaDatabaseTTLs(cfg.MonthsToKeepHistoricalFirstSeen)
	if err != nil {
		return nil, err
	}

	// drop database if rebuild flag was passed
	if rebuildFlag {
		err = server.DeleteSensorDB(dbName)
		if err != nil {
			return nil, err
		}
		logger.Info().Str("database", dbName).Msg("Successfully rebuilt import database")
	}

	rolling, err := server.checkRolling(dbName, rollingFlag, rebuildFlag)
	if err != nil {
		return nil, err
	}

	db, err := server.createSensorDatabase(cfg, dbName, rolling)
	if err != nil {
		return nil, err
	}

	err = db.ResetTemporaryTables()
	if err != nil {
		return nil, err
	}

	err = server.syncThreatIntelFeedsFromConfig(afs, cfg)
	if err != nil {
		return nil, err
	}

	err = server.importValidMIMETypes(cfg)
	if err != nil {
		return nil, err
	}

	// err = server.ParseHints(afs, cfg)
	// if err != nil {
	// 	return nil, err
	// }

	// // set rolling flag
	db.Rolling = rollingFlag

	// set rebuild flag
	db.rebuild = rebuildFlag

	return db, nil

}

// QueryParameters generates ClickHouse query parameters by creating a context with the specified parameters in it
func (server *ServerConn) QueryParameters(params clickhouse.Parameters) context.Context {
	return clickhouse.Context(server.ctx, clickhouse.WithParameters(params))
}

// GetContext returns the context for the database connection
func (server *ServerConn) GetContext() context.Context {
	return server.ctx
}

// getConn returns the driver connection
func (server *ServerConn) getConn() driver.Conn {
	return server.Conn
}

func (server *ServerConn) createHistoricalFirstSeenTable() error {
	err := server.Conn.Exec(context.Background(), `--sql
		CREATE TABLE IF NOT EXISTS metadatabase.historical_first_seen (
			ip IPv6,
			fqdn String,
			first_seen SimpleAggregateFunction(min, DateTime()),
			last_seen SimpleAggregateFunction(max, DateTime())
		) ENGINE = AggregatingMergeTree()
		PRIMARY KEY (fqdn, ip)
	`)
	return err
}

// createSensorDatabase creates a database for the specified sensor and returns a connection to it
func (server *ServerConn) createSensorDatabase(cfg *config.Config, dbName string, rolling bool) (*DB, error) {
	logger := zlog.GetLogger()

	// create a database named after the specified sensor
	ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
		"database": dbName,
	}))

	err := server.Conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS {database:Identifier}")
	if err != nil {
		logger.Err(err).Str("database", dbName).
			Str("database connection", cfg.DBConnection).
			Msg("failed to create sensor database")
		return nil, err
	}

	// connect to newly created database
	db, err := ConnectToDB(server.ctx, dbName, cfg, server.cancel)
	if err != nil {
		logger.Err(err).Str("database", dbName).
			Str("database connection", cfg.DBConnection).
			Msg("failed to connect to sensor database")
		return nil, err
	}

	// set rolling flag
	db.Rolling = rolling

	// create tables for the newly created database
	err = db.createSensorDBTables()
	if err != nil {
		logger.Err(err).Str("database", dbName).
			Str("database connection", cfg.DBConnection).
			Msg("failed to create tables for import database")
		return nil, err
	}
	// create analysis tables for the newly created database
	err = db.createSensorDBAnalysisTables()
	if err != nil {
		logger.Err(err).Str("database", dbName).
			Str("database connection", cfg.DBConnection).
			Msg("failed to create analysis tables for import database")
		return nil, err
	}

	// if the database is rolling, create the necessary TTLs on the tables for cleanup
	if db.Rolling {
		if err := db.createLogTableTTLs(); err != nil {
			return nil, err
		}

		if err := db.createSnapshotTableTTLs(); err != nil {
			return nil, err
		}
	}

	return db, nil
}

// DropMultipleSensorDatabases drops the databases that match the specified wildcard
// a wildcard can be in the beginning, end, or both
func (server *ServerConn) DropMultipleSensorDatabases(dbName string, wildcardStart, wildcardEnd bool) (int, error) {
	var query string
	// switch {
	// case wildcardStart && !wildcardEnd:
	// 	query = "SHOW DATABASES LIKE '%{database:String}'"
	// case !wildcardStart && wildcardEnd:
	// 	query = "SHOW DATABASES LIKE '{database:String}%'"
	// case wildcardStart && wildcardEnd:
	// 	query = "SHOW DATABASES LIKE '%{database:String}%'"
	// case !wildcardStart && !wildcardEnd:
	// 	return 0, errors.New("no wildcard specified for deleting multiple datasets")
	// }

	// create query to get the databases that match the wildcard
	switch {
	case wildcardStart && wildcardEnd:
		query = fmt.Sprintf("SHOW DATABASES LIKE '%%%s%%'", dbName)
	case wildcardStart:
		query = fmt.Sprintf("SHOW DATABASES LIKE '%%%s'", dbName)
	case wildcardEnd:
		query = fmt.Sprintf("SHOW DATABASES LIKE '%s%%'", dbName)
	default:
		return 0, errors.New("no wildcard specified for deleting multiple datasets")
	}

	// execute the query
	paramsCtx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{"database": dbName}))
	rows, err := server.Conn.Query(paramsCtx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	// create a counter to keep track of the number of databases deleted
	var numDeleted int

	// iterate over the databases that match the wildcard
	for rows.Next() {
		// get the database name
		var foundDB string
		err := rows.Scan(&foundDB)
		if err != nil {
			return numDeleted, err
		}

		// drop the database
		err = server.DeleteSensorDB(foundDB)
		if err != nil {
			return numDeleted, err
		}

		// increment the number of databases deleted
		numDeleted++
	}

	return numDeleted, nil
}

// dropSensorDatabase drops the specified sensor database
func (server *ServerConn) dropSensorDatabase(dbName string) error {
	logger := zlog.GetLogger()
	err := dropDatabase(server.ctx, server.Conn, dbName)
	if err != nil {
		logger.Err(err).Str("database", dbName).Msg("failed to drop database")
		return err
	}
	return nil
}

// DeleteSensorDB deletes the specified database along with its associated imported files in metadatabase.files
func (server *ServerConn) DeleteSensorDB(database string) error {
	// drop the database
	if err := server.dropSensorDatabase(database); err != nil {
		return err
	}

	// clear entries in metadatabase
	if err := server.ClearMetaDBEntriesForDatabase(database); err != nil {
		return err
	}

	return nil
}

// GetRollingStatus gets the rolling status of a database
func GetRollingStatus(dbCtx context.Context, conn driver.Conn, dbName string) (bool, error) {
	var result struct {
		Rolling bool `ch:"rolling"`
	}

	// if import database does not exist, return an error
	exists, err := SensorDatabaseExists(dbCtx, conn, dbName)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrDatabaseNotFound
	}

	// check the rolling status by looking at the most recent rebuild
	ctx := clickhouse.Context(dbCtx, clickhouse.WithParameters(clickhouse.Parameters{"database": dbName}))
	err = conn.QueryRow(ctx, `
			SELECT rolling FROM metadatabase.min_max WHERE database = {database:String}
			ORDER BY max_ts DESC
			LIMIT 1
	`).ScanStruct(&result)

	if err != nil {
		return false, err
	}

	return result.Rolling, nil
}

// checkRolling checks the rolling status of a database
func (server *ServerConn) checkRolling(dbName string, rollingFlag bool, rebuildFlag bool) (bool, error) {
	logger := zlog.GetLogger()

	// get the current rolling status of the database from the imports table (if db already exists)
	rolling, err := GetRollingStatus(server.ctx, server.Conn, dbName)

	switch {
	// if database doesn't exist, just return the desired rolling status from flag
	case errors.Is(err, ErrDatabaseNotFound) || errors.Is(err, sql.ErrNoRows):
		return rollingFlag, nil

	// error executing query
	case err != nil:
		logger.Err(err).Str("database", dbName).
			Str("database connection", server.addr).
			Msg(errRollingStatusFailure.Error())
		return rolling, errRollingStatusFailure

	// command is requesting to import data as rolling, but dataset is not rolling
	case rollingFlag && !rolling && !rebuildFlag:
		logger.Warn().Str("database", dbName).
			Msg(ErrImportTwiceNonRolling.Error())
		return rolling, ErrImportTwiceNonRolling

	// command is requesting to import data as non-rolling, but dataset is rolling
	case rolling && !rollingFlag && !rebuildFlag:
		logger.Warn().Str("database", dbName).
			Msg(errRollingFlagMissing.Error())
		return rolling, errRollingFlagMissing
	}

	return rolling, nil
}

type ImportDatabase struct {
	Name    string    `ch:"database"`
	Rolling bool      `ch:"rolling"`
	MinTS   time.Time `ch:"min_ts"`
	MaxTS   time.Time `ch:"max_ts"`
}

func (server *ServerConn) ListImportDatabases() ([]ImportDatabase, error) {
	logger := zlog.GetLogger()

	// if metadatabase does not exist, return an empty list
	exists, err := DatabaseExists(server.ctx, server.Conn, "metadatabase")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	var sensorDBs []ImportDatabase

	// return list of databases based on min_max table
	query := `
		SELECT database, rolling, greatest(min_ts, timestamp_sub(WEEK, 2, max_ts)) as min_ts, max_ts FROM (
			SELECT database, rolling, min(min_ts) AS min_ts, max(max_ts) AS max_ts FROM metadatabase.min_max
			GROUP BY database, rolling
			ORDER BY max_ts DESC
		)
    `
	err = server.Conn.Select(server.ctx, &sensorDBs, query)
	if err != nil {
		logger.Err(err).Str("database connection", server.addr).Msg("failed to execute import database list query")
		return nil, err
	}

	return sensorDBs, nil
}

func SensorDatabaseExists(ctx context.Context, conn driver.Conn, dbName string) (bool, error) {
	logger := zlog.GetLogger()
	// check if database actually exists
	dbExists, err := DatabaseExists(ctx, conn, dbName)
	if err != nil {
		logger.Err(err).Str("database", dbName).Msg("failed to check if database exists")
		return false, err
	}
	if !dbExists {
		return false, nil
	}

	// check if database is listed in metadatabase
	paramsCtx := clickhouse.Context(ctx, clickhouse.WithParameters(clickhouse.Parameters{"database": dbName}))

	var exists uint64
	err = conn.QueryRow(paramsCtx, "SELECT count() FROM metadatabase.min_max WHERE database = {database:String}").Scan(&exists)
	if err != nil {
		logger.Err(err).Str("database", dbName).Msg("failed to check if database exists in metadatabase")
		return false, err
	}
	return exists > 0, nil
}

// GetFlatDatabaseList returns a list of database names from a list of ImportDatabase structs
func GetFlatDatabaseList(dbs []ImportDatabase) []string {
	var dbList []string
	for _, db := range dbs {
		dbList = append(dbList, db.Name)
	}
	return dbList
}

func DatabaseExists(ctx context.Context, conn driver.Conn, dbName string) (bool, error) {
	logger := zlog.GetLogger()

	paramsCtx := clickhouse.Context(ctx, clickhouse.WithParameters(clickhouse.Parameters{"database": dbName}))

	var exists uint64
	err := conn.QueryRow(paramsCtx, "SELECT count() FROM system.databases WHERE name = {database:String}").Scan(&exists)
	if err != nil {
		logger.Err(err).Str("database", dbName).Msg("failed to check if database exists")
		return false, err
	}

	return exists > 0, nil
}

// dropDatabase drops the specified database
func dropDatabase(ctx context.Context, conn driver.Conn, dbName string) error {
	paramsCtx := clickhouse.Context(ctx, clickhouse.WithParameters(clickhouse.Parameters{
		"database": dbName,
	}))
	err := conn.Exec(paramsCtx, "DROP DATABASE IF EXISTS {database:Identifier}")
	if err != nil {
		return err
	}
	return nil
}

// ConnectToServer connects to the clickhouse server as the default user
func ConnectToServer(ctx context.Context, cfg *config.Config) (*ServerConn, error) {
	logger := zlog.GetLogger()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.DBConnection}, // read from env instead
		Auth: clickhouse.Auth{
			Database: "default",
			Username: "default",
			Password: "",
		},
	})

	if err != nil {
		logger.Err(err).Str("database", "default").
			Str("database connection", cfg.DBConnection).
			Msg("failed to connect to ClickHouse server")
		return nil, err
	}

	// ping the server to verify connection
	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}

	return &ServerConn{
		Conn: conn,
		addr: cfg.DBConnection,
		ctx:  ctx,
	}, nil
}
