package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/activecm/rita/v5/config"
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
		INSERT INTO metadatabase.imports (import_id, rolling, database, rebuild, started_at)
		VALUES (unhex({importID:String}), {rolling:Bool}, {database:String}, {rebuild:Bool}, fromUnixTimestamp64Micro({importStartedAt:Int64}))
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
		INSERT INTO metadatabase.imports (import_id, rolling, database, started_at, ended_at, min_timestamp, max_timestamp, min_open_timestamp, max_open_timestamp)
		VALUES (
			unhex({importID:String}), 
			{rolling:Bool}, 
			{database:String}, 
			fromUnixTimestamp64Micro({importStartedAt:Int64}), 
			fromUnixTimestamp({importEndedAt:Int32}), 
			fromUnixTimestamp({minTs:Int32}), 
			fromUnixTimestamp({maxTs:Int32}), 
			fromUnixTimestamp({minOpenTs:Int32}), 
			fromUnixTimestamp({maxOpenTs:Int32})
		)
	`)
	return err
}

// CheckIfFilesWereAlreadyImported calls checkFileHashes for each log type
func (db *DB) CheckIfFilesWereAlreadyImported(fileMap map[string][]string) (int, error) {
	totalFileCount := 0
	// loop over each log type in the hour's filemap
	for logType, logList := range fileMap {
		results, err := db.checkFileHashes(logList)
		if err != nil {
			return totalFileCount, err
		}
		fileMap[logType] = results
		totalFileCount += len(results)
	}

	return totalFileCount, nil
}

// checkFileHashes filters fileList to only files that haven't already been imported for this dataset
func (db *DB) checkFileHashes(fileList []string) ([]string, error) {
	// format array for clickhouse parameters
	files := "["
	for _, file := range fileList {
		files += fmt.Sprintf("'%s',", file)
	}
	files += "]"

	ctx := db.QueryParameters(clickhouse.Parameters{
		"database": db.selected,
		"files":    files,
	})

	var importedFiles []struct {
		Path string `ch:"path"`
	}

	// query for files in this fileList that have already been imported
	err := db.Conn.Select(ctx, &importedFiles, `
		SELECT path FROM metadatabase.files WHERE database = {database:String} AND path IN {files:Array(String)}
	`)
	if err != nil {
		return nil, err
	}

	// convert imported files array into a map
	importedFilesMap := make(map[string]bool)
	for _, file := range importedFiles {
		importedFilesMap[file.Path] = true
	}

	var nonImportedFiles []string

	// build a list of files that haven't been imported
	for _, file := range fileList {
		if !importedFilesMap[file] {
			nonImportedFiles = append(nonImportedFiles, file)
		}
	}

	return nonImportedFiles, err
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
