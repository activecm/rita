package integration_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/activecm/rita/cmd"
	"github.com/activecm/rita/config"
	"github.com/activecm/rita/database"
	i "github.com/activecm/rita/importer"
	"github.com/activecm/rita/util"

	fp "path/filepath"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func CheckImportFileTracking(t *testing.T, importer *i.Importer) { // uses valid dataset
	t.Helper()
	var result struct {
		Count uint64 `ch:"count"`
	}

	// set context with importID and database parameters
	ctx := clickhouse.Context(importer.Database.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"importID": importer.ImportID.Hex(),
		"database": importer.Database.GetSelectedDB(),
	}))

	// make sure total (post duplicate filtering) file count to be imported matches file count in metadb
	err := importer.Database.Conn.QueryRow(ctx, `
			SELECT count() AS count FROM metadatabase.files
			WHERE import_id = unhex({importID:String}) AND database = {database:String}
		`).ScanStruct(&result)
	require.NoError(t, err)
	require.EqualValues(t, importer.TotalFileCount, result.Count, "total file count matches imported file count")

	var allFiles []string
	allFiles = append(allFiles, importer.FileMap[i.ConnPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.OpenConnPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.HTTPPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.OpenHTTPPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.SSLPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.OpenSSLPrefix]...)
	allFiles = append(allFiles, importer.FileMap[i.DNSPrefix]...)

	var filesResult struct {
		Files []string `ch:"files"`
	}

	// set context with importID parameter
	ctx = clickhouse.Context(importer.Database.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"importID": importer.ImportID.Hex(),
	}))

	// make sure all files in created filemap were imported and saved in metadb
	err = importer.Database.Conn.QueryRow(ctx, `
			SELECT groupArray(path) as files FROM metadatabase.files
			WHERE import_id = unhex({importID:String})
		`).ScanStruct(&filesResult)
	require.NoError(t, err)
	require.ElementsMatch(t, allFiles, filesResult.Files, "files in filemap created for import match list of imported files in metadb")

	// Make sure duplicate files in same import don't get imported (conn.log & conn.log.gz)
	for _, file := range allFiles {
		if strings.HasSuffix(file, ".gz") {
			hasUncompressedDuplicate := slices.Contains(allFiles, strings.TrimSuffix(file, ".gz"))
			require.False(t, hasUncompressedDuplicate, "ucompressed duplicate of .gz file was not imported")
		} else {
			hasCompressedDuplicate := slices.Contains(allFiles, (file + ".gz"))
			require.False(t, hasCompressedDuplicate, "compressed duplicate of uncompressed file was not imported")
		}
	}

	// importing again should fail because all files are imported
	err = importer.Import(afero.NewOsFs(), importer.FileMap)
	require.Error(t, err)

}

func TestImportTracking(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	// load config
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	// update config with clickhouse connection
	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not produce an error")

	// ROLLING IMPORT
	// new import
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/open_conns/closed", "test_import_rolling", true, false)
	require.NoError(t, err, "new rolling import should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_rolling", cfg, nil)
	require.NoError(t, err)

	// import another folder
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/open", "test_import_rolling", true, false)
	require.NoError(t, err, "importing another folder to a rolling database should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_rolling", cfg, nil)
	require.NoError(t, err)

	// rebuild dataset
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/open", "test_import_rolling", true, true)
	require.NoError(t, err, "importing same folder to a rebuilt rolling database should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_rolling", cfg, nil)
	require.NoError(t, err)

	// ***************************************************************************
	// NON-ROLLING IMPORT
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/closed", "test_import_nonrolling", false, true)
	require.NoError(t, err, "new non-rolling import should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_nonrolling", cfg, nil)
	require.NoError(t, err)

	// import another folder
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/closed", "test_import_nonrolling", false, false)
	require.Error(t, err, "importing another folder to a non-rolling database should not succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_nonrolling", cfg, nil)
	require.NoError(t, err)

	// rebuild dataset
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/closed", "test_import_nonrolling", false, true)
	require.NoError(t, err, "importing same folder to a rebuilt non-rolling database should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_nonrolling", cfg, nil)
	require.NoError(t, err)

	// rebuild dataset & convert to rolling
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/open", "test_import_nonrolling", true, true)
	require.NoError(t, err, "importing once to a non-rolling database converted to a rolling database should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_nonrolling", cfg, nil)
	require.NoError(t, err)

	// import again to rolling dataset
	_, err = cmd.RunImportCmd(time.Now(), cfg, afero.NewOsFs(), TestDataPath+"/open_conns/closed", "test_import_nonrolling", true, true)
	require.NoError(t, err, "importing twice to a converted rolling database should succeed")
	// connect to database
	_, err = database.ConnectToDB(context.Background(), "test_import_nonrolling", cfg, nil)
	require.NoError(t, err)

}

// TestMinMaxTimestamps tests that the min and max timestamps are correctly stored in the metadatabase.imports table
func TestMinMaxTimestamps(t *testing.T) {

	// set up file system interface
	afs := afero.NewOsFs()

	// load config
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)
	err = cfg.ResetConfig()
	require.NoError(t, err)
	cfg, err = config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)
	// update config with clickhouse connection
	cfg.DBConnection = dockerInfo.clickhouseConnection
	require.True(t, cfg.Filter.FilterExternalToInternal)
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not produce an error")

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), cfg)
	require.NoError(t, err, "connecting to server should not produce an error")

	err = server.Conn.Exec(server.GetContext(), "TRUNCATE TABLE IF EXISTS metadatabase.imports")
	require.NoError(t, err)

	err = server.Conn.Exec(server.GetContext(), "TRUNCATE TABLE IF EXISTS metadatabase.min_max")
	require.NoError(t, err)

	t.Run("Open Dataset", func(t *testing.T) {

		// open dataset
		results, err := cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/open_conns/open", "test_minmax_open", false, true)
		require.NoError(t, err, "import should succeed")

		// connect to database
		db, err := database.ConnectToDB(context.Background(), "test_minmax_open", cfg, nil)
		require.NoError(t, err)

		minTSBeacon := 1517420070
		maxTSBeacon := 1517422419
		minTS := 1517336019
		maxTS := 1517422419
		minOpenTS := 1517336042
		maxOpenTS := 1517336223

		// validate metadb imports table values for min/max (these are used for troubleshooting)
		min, max, minOpen, maxOpen := getMinMaxTimestamps(t, db, results.ImportID[0])
		require.EqualValues(t, minTS, min.Unix(), "imports: min timestamp matches expected min timestamp: open_conns/open")
		require.EqualValues(t, maxTS, max.Unix(), "imports: max timestamp matches expected max timestamp: open_conns/open")
		require.EqualValues(t, minOpenTS, minOpen.Unix(), "imports: min open timestamp matches expected min open timestamp: open_conns/open")
		require.EqualValues(t, maxOpenTS, maxOpen.Unix(), "imports: max open timestamp matches expected max open timestamp: open_conns/open")

		// validate metadb min_max values for min/max
		min, max, notFromConn, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "getting true min/max timestamps should not error")
		require.EqualValues(t, minTS, min.Unix(), "min_max: min timestamp matches expected min timestamp: open_conns/open")
		require.EqualValues(t, maxTS, max.Unix(), "min_max: max timestamp matches expected max timestamp: open_conns/open")

		// validate which table min max is from
		require.False(t, notFromConn, "min and max timestamps should be from conn table")
		require.False(t, useCurrentTime, "first seen analysis should not use the current time")

		min, max, notFromConn, err = db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "getting beacon min/max timestamps should not error")
		require.EqualValues(t, minTSBeacon, min.Unix(), "min_max: beacon min timestamp matches expected min timestamp: open_conns/open")
		require.EqualValues(t, maxTSBeacon, max.Unix(), "min_max: beacon max timestamp matches expected max timestamp: open_conns/open")

		// validate which table min max is from
		require.False(t, notFromConn, "min and max timestamps should be from conn table")

	})

	t.Run("Closed Dataset", func(t *testing.T) {

		// closed dataset
		results, err := cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/valid_tsv", "test_minmax", false, true)
		require.NoError(t, err, "import should succeed")

		// connect to database
		db, err := database.ConnectToDB(context.Background(), "test_minmax", cfg, nil)
		require.NoError(t, err)

		min, max, minOpen, maxOpen := getMinMaxTimestamps(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		minTS := 1517336040 // isn't 1517336042 because DNS rounds to start of hour
		minOpenTS := 1517336042
		maxTS := 1517422440
		minTSBeacon := 1517336042
		maxTSBeacon := 1517422440

		// validate metadb imports table values for min/max (these are used for troubleshooting)
		require.EqualValues(t, minTS, min.Unix(), "imports: min timestamp matches expected min timestamp: valid_tsv")
		require.EqualValues(t, maxTS, max.Unix(), "imports: max timestamp matches expected max timestamp: valid_tsv")
		require.EqualValues(t, minOpenTS, minOpen.Unix(), "imports: min open timestamp should be unset: valid_tsv")
		require.EqualValues(t, maxTS, maxOpen.Unix(), "imports: max open timestamp should be unset: valid_tsv")

		// validate metadb min_max values for min/max
		min, max, notFromConn, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "getting min/max timestamps should not error")
		require.EqualValues(t, minTS, min.Unix(), "min_max: min timestamp matches expected min timestamp: open_conns/open")
		require.EqualValues(t, maxTS, max.Unix(), "min_max: max timestamp matches expected max timestamp: open_conns/open")

		require.False(t, notFromConn, "min and max timestamps should be from conn table")
		require.False(t, useCurrentTime, "first seen analysis should not use the current time")

		min, max, notFromConn, err = db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "getting min/max timestamps should not error")
		require.EqualValues(t, minTSBeacon, min.Unix(), "min_max: beacon min timestamp matches expected min timestamp: open_conns/open")
		require.EqualValues(t, maxTSBeacon, max.Unix(), "min_max: beacon max timestamp matches expected max timestamp: open_conns/open")

		require.False(t, notFromConn, "min and max timestamps should be from conn table")

	})
}

func getMinMaxTimestamps(t *testing.T, db *database.DB, importID util.FixedString) (time.Time, time.Time, time.Time, time.Time) { // uses valid dataset
	t.Helper()

	type minMaxRes struct {
		Min     time.Time `ch:"min_timestamp"`
		Max     time.Time `ch:"max_timestamp"`
		MinOpen time.Time `ch:"min_open_timestamp"`
		MaxOpen time.Time `ch:"max_open_timestamp"`
	}

	var result minMaxRes

	// set context with importID and database parameters
	ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"importID": importID.Hex(),
		"database": db.GetSelectedDB(),
	}))

	// make sure min and max timestamps are correct in the metadatabase.imports record
	err := db.Conn.QueryRow(ctx, `
			SELECT min_timestamp, max_timestamp, min_open_timestamp, max_open_timestamp FROM metadatabase.imports
			WHERE import_id = unhex({importID:String}) AND database = {database:String}
			ORDER BY ended_at DESC
		`).ScanStruct(&result)
	require.NoError(t, err)
	return result.Min, result.Max, result.MinOpen, result.MaxOpen
}

func TestMetaDatabase(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	// load config
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not produce an error")

	// import a dataset
	dbName := "test_metadb"
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/valid_tsv", dbName+"_tsv", false, true)
	require.NoError(t, err, "import should succeed")
	importID := results.ImportID[0]

	// import a few other datasets for testing multiple metadb entries
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/valid_json", dbName+"_json", false, true)
	require.NoError(t, err, "import should succeed")
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, TestDataPath+"/open_conns/open", dbName+"_open", false, true)
	require.NoError(t, err, "import should succeed")

	// connect to metadatabase
	db, err := database.ConnectToDB(context.Background(), "metadatabase", cfg, nil)
	require.NoError(t, err)

	// test metadatabase tables
	t.Run("Imports Table", func(t *testing.T) {
		validateMetaDBImportsTable(t, db, dbName+"_tsv", importID)
	})
	t.Run("Files Table", func(t *testing.T) {
		validateMetaDBFilesTable(t, db, TestDataPath+"/valid_tsv", dbName+"_tsv", importID)
	})
	validateMetaDBHistoricalFirstSeenTable(t)
	validateMetaDBValidMimeTypesTable(t)

}
func validateMetaDBImportsTable(t *testing.T, db *database.DB, dbName string, importID util.FixedString) {
	t.Helper()

	// set the context
	ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"table":    "imports",
		"database": dbName,
		"importID": importID.Hex(),
	}))

	var result struct {
		Count uint64 `ch:"count"`
	}

	// imports table exists
	t.Run("Table Exists", func(t *testing.T) {
		var exists uint8
		err := db.Conn.QueryRow(ctx, `EXISTS TABLE {table:Identifier}`).Scan(&exists)
		require.NoError(t, err)
		require.EqualValues(t, 1, exists, "imports table exists")
	})

	// verify that start and end import records for first import were created
	t.Run("Record Matches", func(t *testing.T) {
		err := db.Conn.QueryRow(ctx, `
			SELECT count() AS count 
			FROM {table:Identifier}
			WHERE database = {database:String} AND import_id = unhex({importID:String})
			`).ScanStruct(&result)

		require.NoError(t, err)
		// 2 import records should be created, one at the start of the import and one when the import is finished
		require.EqualValues(t, 2, result.Count, "expected 2 import records to be created, got %d", result.Count)
	})

	// no import record has unset import_id
	t.Run("No Unset ImportID", func(t *testing.T) {
		err := db.Conn.QueryRow(ctx, `
			SELECT count() AS count 
			FROM {table:Identifier}
			WHERE import_id==toFixedString('',16) OR hex(import_id)=='00000000000000000000000000000000' OR import_id=='' OR import_id IS NULL
			`).ScanStruct(&result)

		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "imports table must not have unset import_id fields")
	})

	// no import record has unset database
	t.Run("No Unset Database", func(t *testing.T) {
		err := db.Conn.QueryRow(ctx, `
			SELECT count() AS count 
			FROM {table:Identifier}
			WHERE database=='' OR database IS NULL
			`).ScanStruct(&result)

		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "imports table must not have unset database fields")
	})

}

func validateMetaDBFilesTable(t *testing.T, db *database.DB, directory string, dbName string, importID util.FixedString) {
	t.Helper()

	// set the context
	ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"table":    "files",
		"database": dbName,
		"importID": importID.Hex(),
	}))

	// files table exists
	t.Run("Table Exists", func(t *testing.T) {
		var exists uint8
		err := db.Conn.QueryRow(ctx, `EXISTS TABLE {table:Identifier}`).Scan(&exists)
		require.NoError(t, err)
		require.EqualValues(t, 1, exists, "files table must exist")
	})

	// verify that files entries for import are correct
	t.Run("Files List Correct", func(t *testing.T) {

		// get the files listed in the files table for the first import
		rows, err := db.Conn.Query(ctx, `
				SELECT path
				FROM {table:Identifier}
				WHERE database = {database:String} AND import_id = unhex({importID:String})
			`)
		require.NoError(t, err)
		defer rows.Close()

		// type fileVersions

		// map to track the versions of each file
		dbFiles := make(map[string]struct {
			log   bool
			logGz bool
		})

		for rows.Next() {
			var result struct {
				Path string `ch:"path"`
			}
			err = rows.ScanStruct(&result)
			require.NoError(t, err)

			// get the filename without the path
			name := fp.Base(result.Path)

			// set map key as the filename without the .gz extension
			normalizedFilename := strings.TrimSuffix(name, ".gz")

			// get the version info for the file
			versionInfo := dbFiles[normalizedFilename]

			// set the version info for the file
			if strings.HasSuffix(name, ".gz") {
				versionInfo.logGz = true
			} else {
				versionInfo.log = true
			}

			// update the map
			dbFiles[normalizedFilename] = versionInfo
		}

		// get all files in the directory
		fs := afero.NewOsFs()
		allFiles, err := afero.ReadDir(fs, directory)
		require.NoError(t, err)

		// check that a single version (log or log.gz) of each file is present in the database
		for _, file := range allFiles {
			normalizedFileName := strings.TrimSuffix(file.Name(), ".gz")

			if normalizedFileName == ".DS_Store" {
				continue
			}

			versions, exists := dbFiles[normalizedFileName]

			// check that a version of the file exists in the database
			require.True(t, exists, "file must exist in database records: %s", normalizedFileName)

			// verify that only one version of the file is present in the database
			require.False(t, versions.log && versions.logGz, "both .log and .log.gz versions cannot be present in the database")
		}
	})
}

func validateMetaDBHistoricalFirstSeenTable(t *testing.T) {
	t.Helper()
}

func validateMetaDBValidMimeTypesTable(t *testing.T) {
	t.Helper()
}
