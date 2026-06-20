package database

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/activecm/rita/v5/config"
	c "github.com/activecm/rita/v5/constants"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
)

type MetaDBImportedFile struct {
	Hash      *util.FixedString `ch:"hash"`
	ImportID  *util.FixedString `ch:"import_id"`
	Database  string            `ch:"database"`
	Timestamp time.Time         `ch:"ts"`
	Path      string            `ch:"path"`
}

type MetaDBImportRecord struct {
	ImportID         *util.FixedString `ch:"import_id"`
	Rolling          bool              `ch:"rolling"`
	Database         string            `ch:"database"`
	Rebuild          bool              `ch:"rebuild"`
	StartedAt        int64             `ch:"started_at"`
	EndedAt          time.Time         `ch:"ended_at"`
	HoursSeen        []time.Time       `ch:"hours_seen"`
	ImportVersion    string            `ch:"import_version"`
	MinTimestamp     time.Time         `ch:"min_timestamp"`
	MaxTimestamp     time.Time         `ch:"max_timestamp"`
	MinOpenTimestamp time.Time         `ch:"min_open_timestamp"`
	MaxOpenTimestamp time.Time         `ch:"max_open_timestamp"`
}

// createMetaDatabase creates the metadatabase and its tables if any part of it doesn't exist
func (server *ServerConn) createMetaDatabase() error {
	if err := server.Conn.Exec(server.ctx, `
		CREATE DATABASE IF NOT EXISTS metadatabase
	`); err != nil {
		return err
	}

	if err := server.createMetaDatabaseImportsTable(); err != nil {
		return err
	}

	if err := server.createMetaDatabaseFilesTable(); err != nil {
		return err
	}

	if err := server.createMetaDatabaseMinMaxTable(); err != nil {
		return err
	}

	if err := server.createMetaDatabaseSampleDBsTable(); err != nil {
		return err
	}

	if err := server.createMetaDatabasePerformedZoneTransfersTable(); err != nil {
		return err
	}

	if err := server.createMetaDatabaseZoneTransferTable(); err != nil {
		return err
	}

	if err := server.createThreatIntelTables(); err != nil {
		return err
	}

	if err := server.createValidMIMETypeTable(); err != nil {
		return err
	}

	if err := server.createHistoricalFirstSeenTable(); err != nil {
		return err
	}

	return nil
}

// createMetaDatabaseFilesTable creates the metadatabase.files table
func (server *ServerConn) createMetaDatabaseFilesTable() error {
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.files (
			hash FixedString(16),
			database String,
			import_id FixedString(16),
			rolling Bool,
			ts DateTime(),
			path String
		)
		ENGINE = MergeTree()
		PRIMARY KEY (database, import_id, hash, path)
	`)

	return err
}

// createMetaDatabaseImportsTable creates the metadatabase.imports table
func (server *ServerConn) createMetaDatabaseImportsTable() error {
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.imports (
			import_id FixedString(16),
			rolling Bool,
			database String,
			rebuild Bool,
			-- started_at is measured in Microseconds
			started_at DateTime64(6), 
			ended_at DateTime(),
			hours_seen Array(DateTime()),
			import_version String,
			min_timestamp DateTime(),
			max_timestamp DateTime(),
			min_open_timestamp DateTime(),
			max_open_timestamp DateTime()
		)
		ENGINE = MergeTree()
		PRIMARY KEY (database, ended_at, started_at, import_id)
	`)
	return err
}

func (server *ServerConn) createMetaDatabaseMinMaxTable() error {
	// err := server.Conn.Exec(server.ctx, `--sql
	// 	CREATE TABLE IF NOT EXISTS metadatabase.min_max_raw (
	// 		database String,
	// 		rolling Bool,
	// 		beacon String,
	// 		min_ts DateTime(),
	// 		max_ts DateTime()
	// 	)
	// 	ENGINE = MergeTree()
	// 	PRIMARY KEY (database)
	// `)
	// if err != nil {
	// 	return err
	// }

	err := server.Conn.Exec(server.ctx, `--sql
		CREATE TABLE IF NOT EXISTS metadatabase.min_max (
			database String,
			rolling Bool,
			beacon Bool,
			min_ts SimpleAggregateFunction(min, DateTime()),
			max_ts SimpleAggregateFunction(max, DateTime())
		)
		ENGINE = AggregatingMergeTree()
		PRIMARY KEY (database, beacon)
	`)
	if err != nil {
		return err
	}

	// if err := server.Conn.Exec(server.ctx, `--sql
	// 	CREATE MATERIALIZED VIEW IF NOT EXISTS metadatabase.min_max_default_mv
	// 	TO metadatabase.min_max AS
	// 	SELECT
	// 		database,
	// 		rolling,
	// 		beacon,
	// 		minSimpleState(min_ts) as min_ts,
	// 		maxSimpleState(max_ts) as max_ts
	// 	FROM metadatabase.min_max_raw
	// 	GROUP BY (database, rolling, beacon)
	// `); err != nil {
	// 	return err
	// }
	return nil
}

func (server *ServerConn) createMetaDatabasePerformedZoneTransfersTable() error {
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.performed_zone_transfers (
			domain_name String,
			name_server String,
			serial_soa UInt32,
			mbox String,
			is_ixfr Bool, -- for debugging
			performed_at DateTime()
		)
		ENGINE = ReplacingMergeTree(performed_at)
		PRIMARY KEY (domain_name, name_server)
	`)

	return err
}

func (server *ServerConn) createMetaDatabaseZoneTransferTable() error {
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.zone_transfer (
		performed_at DateTime(),
		domain_name String,
		name_server String,
		hostname String,
		ip IPv6,
		ttl Int32, -- RFC2181 defines TTLs as int32
	) ENGINE = MergeTree()
	PRIMARY KEY (domain_name, name_server, hostname, ip) 
	ORDER BY (domain_name, name_server, hostname, ip, performed_at)
	`)

	return err
}

// createMetaDatabaseFilesTable creates the metadatabase.files table
func (server *ServerConn) createMetaDatabaseSampleDBsTable() error {
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.sample_dbs (
			name String,
		)
		ENGINE = ReplacingMergeTree()
		PRIMARY KEY (name)
		ORDER BY (name)
	`)

	return err
}

// MarkFileImportedInMetaDB adds the given path to the metadatabase.files table to mark it as being used
func (db *DB) MarkFileImportedInMetaDB(hash util.FixedString, importID util.FixedString, path string) error {
	ctx := db.QueryParameters(clickhouse.Parameters{
		"hash":      hash.Hex(),
		"importID":  importID.Hex(),
		"database":  db.selected,
		"timestamp": strconv.FormatInt(time.Now().UTC().Unix(), 10),
		"path":      path,
		"rolling":   strconv.FormatBool(db.Rolling),
	})

	err := db.Conn.Exec(ctx, `
		INSERT INTO metadatabase.files (hash, import_id, database, rolling, ts, path)
		VALUES (unhex({hash:String}), unhex({importID:String}), {database:String}, {rolling:Bool}, {timestamp:Int32}, {path:String})
	`)
	return err
}

/* *** TRACKING IMPORTS ***
Data in ClickHouse is meant to be append-only. This means that we cannot easily update records.
The metadatabase.imports table acts as a log of events for imports. In order to track the start and completion
of an import, one record is inserted at the beginning of the import, and another record is imported at the end.
*/

// AddImportStartRecordToMetaDB inserts a record into the metadatabase.imports table to mark that an import has started
func (db *DB) AddImportStartRecordToMetaDB(importID util.FixedString) error {
	if config.Version == "" {
		return fmt.Errorf("cannot add import record to metadb, version is not set")
	}
	ctx := db.QueryParameters(clickhouse.Parameters{
		"importID":        importID.Hex(),
		"rolling":         strconv.FormatBool(db.Rolling),
		"database":        db.selected,
		"rebuild":         strconv.FormatBool(db.rebuild),
		"importStartedAt": strconv.FormatInt(db.ImportStartedAt.UnixMicro(), 10),
		"importVersion":   config.Version,
	})

	err := db.Conn.Exec(ctx, `
		INSERT INTO metadatabase.imports (import_id, rolling, database, rebuild, started_at, import_version)
		VALUES (unhex({importID:String}), {rolling:Bool}, {database:String}, {rebuild:Bool}, fromUnixTimestamp64Micro({importStartedAt:Int64}), {importVersion:String})
	`)

	return err
}

// AddImportFinishedRecordToMetaDB inserts a record into the metadatabase.imports table to mark that an import has finished
func (db *DB) AddImportFinishedRecordToMetaDB(importID util.FixedString, minTS, maxTS time.Time) error {
	// get min and max timestamps from the imported conn logs
	type minMaxRes struct {
		Min time.Time `ch:"min_ts"`
		Max time.Time `ch:"max_ts"`
	}

	// get min and max timestamps from the imported open_conn logs
	var minMaxOpen minMaxRes

	err := db.Conn.QueryRow(db.GetContext(), `
		SELECT min(ts) as min_ts, max(ts) as max_ts FROM openconn
	`).ScanStruct(&minMaxOpen)
	if err != nil {
		return err
	}

	ctx := db.QueryParameters(clickhouse.Parameters{
		"importID":        importID.Hex(),
		"rolling":         strconv.FormatBool(db.Rolling),
		"database":        db.selected,
		"importStartedAt": strconv.FormatInt(db.ImportStartedAt.UnixMicro(), 10),
		"importEndedAt":   strconv.FormatInt(time.Now().Unix(), 10),
		"minTs":           strconv.FormatInt(minTS.UTC().Unix(), 10),
		"maxTs":           strconv.FormatInt(maxTS.UTC().Unix(), 10),
		"minOpenTs":       strconv.FormatInt(minMaxOpen.Min.UTC().Unix(), 10),
		"maxOpenTs":       strconv.FormatInt(minMaxOpen.Max.UTC().Unix(), 10),
		"importVersion":   config.Version,
	})

	err = db.Conn.Exec(ctx, `
		INSERT INTO metadatabase.imports (import_id, rolling, database, started_at, ended_at, min_timestamp, max_timestamp, min_open_timestamp, max_open_timestamp, import_version)
		VALUES (
			unhex({importID:String}), 
			{rolling:Bool}, 
			{database:String}, 
			fromUnixTimestamp64Micro({importStartedAt:Int64}), 
			fromUnixTimestamp({importEndedAt:Int32}), 
			fromUnixTimestamp({minTs:Int32}), 
			fromUnixTimestamp({maxTs:Int32}), 
			fromUnixTimestamp({minOpenTs:Int32}), 
			fromUnixTimestamp({maxOpenTs:Int32}),
			{importVersion:String}
		)
	`)
	return err
}

// CheckIfFilesWereAlreadyImported calls checkFileHashes for each log type
func (db *DB) CheckIfFilesWereAlreadyImported(fileMap map[string][]string, mtimes map[string]time.Time) (int, error) {
	totalFileCount := 0
	// loop over each log type in the hour's filemap
	for logType, logList := range fileMap {
		results, err := db.checkFileHashes(logList, mtimes)
		if err != nil {
			return totalFileCount, err
		}
		fileMap[logType] = results
		totalFileCount += len(results)
	}

	// don't bother validating log combinations if there are no new logs
	if totalFileCount == 0 {
		return 0, nil
	}

	// we must validate the log combinations after checking the logs against the metadb
	// because if this is a rolling import and an import was killed/failed somehow and the remaining
	// logs to import are an invalid combination, they need to be filtered out/skipped or else
	// the import can end up hanging
	totalFiles := ValidateLogCombinations(fileMap)

	return totalFiles, nil
}

// ValidateLogCombinations filters out invalid log combinations and returns the number of valid logs to import
// This function is in this package because it needs to be used by both the cmd package and the import or database package
// and this avoids an import cycle
func ValidateLogCombinations(hourMap map[string][]string) int {
	logger := zlog.GetLogger()

	totalHourFilesFound := 0
	// if there are no conn logs in the hour, we have to skip any SSL and HTTP logs for that hour
	if len(hourMap[c.ConnPrefix]) == 0 && (len(hourMap[c.SSLPrefix]) > 0 || len(hourMap[c.HTTPPrefix]) > 0) {
		logger.Warn().Msg("SSL / HTTP logs are present, but no conn logs exist, skipping SSL / HTTP logs...")
		delete(hourMap, c.SSLPrefix)
		delete(hourMap, c.HTTPPrefix)
	}

	// 	// if there are no open conn logs in the hour, we have to skip any open SSL and open HTTP logs for that hour
	if len(hourMap[c.OpenConnPrefix]) == 0 && (len(hourMap[c.OpenSSLPrefix]) > 0 || len(hourMap[c.OpenHTTPPrefix]) > 0) {
		logger.Warn().Msg("Open SSL / open HTTP logs are present, but no conn logs exist, skipping open SSL / open HTTP logs...")
		delete(hourMap, c.OpenSSLPrefix)
		delete(hourMap, c.OpenHTTPPrefix)
	}

	// track the total number of files after filtering out invalid file combinations
	for zeekType := range hourMap {
		// sort the files for each log type, necessary for tests
		slices.Sort(hourMap[zeekType])
		totalHourFilesFound += len(hourMap[zeekType])
	}

	return totalHourFilesFound
}

// checkFileHashes filters fileList to only files that haven't already been imported for this dataset.
// The dedup key is hash(path + mtime_unix), so a file at the same path but with a newer mtime is
// treated as a new file (handles rolling/appended logs like Zeek's conn.log).
func (db *DB) checkFileHashes(fileList []string, mtimes map[string]time.Time) ([]string, error) {
	// compute hex-encoded hash for each file using path + mtime
	type fileEntry struct {
		path    string
		hashHex string
	}
	entries := make([]fileEntry, 0, len(fileList))
	for _, file := range fileList {
		mtime := mtimes[file]
		h, err := util.NewFixedStringHash(file, strconv.FormatInt(mtime.Unix(), 10))
		if err != nil {
			return nil, fmt.Errorf("could not hash file path %q: %w", file, err)
		}
		entries = append(entries, fileEntry{path: file, hashHex: h.Hex()})
	}

	// build the hash array parameter for clickhouse
	hashes := "["
	for _, e := range entries {
		hashes += fmt.Sprintf("'%s',", e.hashHex)
	}
	hashes += "]"

	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
		"hashes":   hashes,
	})

	var importedHashes []struct {
		Hash string `ch:"hash_hex"`
	}

	// query for hashes that have already been imported
	err := db.Conn.Select(ctx, &importedHashes, `
		SELECT hex(hash) AS hash_hex FROM metadatabase.files WHERE database = {database:String} AND hex(hash) IN {hashes:Array(String)}
	`)
	if err != nil {
		return nil, err
	}

	importedSet := make(map[string]bool, len(importedHashes))
	for _, row := range importedHashes {
		importedSet[row.Hash] = true
	}

	var nonImportedFiles []string
	for _, e := range entries {
		if !importedSet[e.hashHex] {
			nonImportedFiles = append(nonImportedFiles, e.path)
		}
	}

	return nonImportedFiles, nil
}

// ClearMetaDBEntriesForDatabase deletes all file and import record entries in the metadatabase for the specified database
func (server *ServerConn) ClearMetaDBEntriesForDatabase(database string) error {
	// verify that the metadatabase exists
	exists, err := DatabaseExists(server.ctx, server.Conn, "metadatabase")
	if err != nil {
		return err
	}

	// clear the imported files and min_max records for the specified database if metadatabase exists
	if exists {
		if err := server.clearImportedFilesFromMetaDB(database); err != nil {
			return err
		}

		if err := server.clearDatabaseFromMetaDB(database); err != nil {
			return err
		}
	}

	return nil
}

// clearImportedFilesFromMetaDB deletes entries in files table for specified database
func (server *ServerConn) clearImportedFilesFromMetaDB(database string) error {
	ctx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{"database": database}))
	err := server.Conn.Exec(ctx, `
		DELETE FROM metadatabase.files WHERE database = {database:String}
	`, database)
	return err
}

func (server *ServerConn) clearDatabaseFromMetaDB(database string) error {
	ctx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{"database": database}))
	if err := server.Conn.Exec(ctx, `
		DELETE FROM metadatabase.min_max WHERE database = {database:String}
	`, database); err != nil {
		return fmt.Errorf("unable to delete database from metadatabase.min_max: %w", err)
	}

	if err := server.Conn.Exec(ctx, `
		DELETE FROM metadatabase.sample_dbs WHERE name = {database:String}
	`, database); err != nil {
		return fmt.Errorf("unable to delete database from metadatabase.sample_dbs: %w", err)
	}
	return nil
}
