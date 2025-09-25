package cmd_test

import (
	"context"
	"fmt"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/constants"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/importer"
	"github.com/activecm/rita/v5/util"

	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

/*
REAL LIFE ZEEK

- /opt/zeek/logs
  - sensor1
  - 2024-05-01
  - 2024-05-02

- /opt/zeek/logs
  - 2024-05-01
  - 2024-05-02

NON-ROLLING LOGS
- some folder
  - conn.log
  - dns.log
  - http.log
  - ssl.log

- open_conn.log

- some folder
  - conn.log
  - sensor1
  - conn.log
  - 2024-05-01
  - 2024-05-02
*/

func (c *CmdTestSuite) TestRunImportCmd() {
	type importDB struct {
		name           string
		logDir         string
		hours          [][]string
		rolling        bool
		rebuild        bool
		expectedImport int
		expectedError  error
	}

	type TestCase struct {
		name      string
		afs       afero.Fs
		importDBs []importDB
		// dbName         string
		// rolling        bool
		// rebuild        bool
		// logDir         string
		// hours          [][]string
		// expectedImport int
		// expectedError error
	}

	testCases := []TestCase{
		{
			name: "No Subdirectories, No Hours",
			afs:  afero.NewOsFs(),
			importDBs: []importDB{
				{
					name:           "ahhhhhhhhhh",
					logDir:         "../test_data/valid_tsv",
					hours:          [][]string{{"conn.log.gz", "dns.log.gz", "http.log.gz", "ssl.log.gz", "open_conn.log.gz", "open_http.log.gz", "open_ssl.log.gz"}},
					rolling:        false,
					rebuild:        false,
					expectedImport: 1,
					expectedError:  nil,
				},
			},
		},
		{
			name: "Simple, SubDirectories - Multi-Day Logs",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs",
					hours: [][]string{
						{"2024-04-29/conn.log", "2024-04-29/dns.log", "2024-04-29/http.log", "2024-04-29/ssl.log", "2024-04-29/open_conn.log", "2024-04-29/open_http.log", "2024-04-29/open_ssl.log"},
						{"2024-05-01/conn.log", "2024-05-01/dns.log", "2024-05-01/http.log", "2024-05-01/ssl.log", "2024-05-01/open_conn.log", "2024-05-01/open_http.log", "2024-05-01/open_ssl.log", "2024-05-01/ssl_blue.log"},
					},
					rolling:        false,
					rebuild:        false,
					expectedImport: 2,
					expectedError:  nil,
				},
			},
		},
		{
			name: "SubDirectories, Multi-Day, Multi-Hour Logs",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs",
					hours: [][]string{
						{"2024-04-29/conn.00:00:00-01:00:00.log", "2024-04-29/open_conn.00:00:00-01:00:00.log", "2024-04-29/dns.00:00:00-01:00:00.log", "2024-04-29/http.00:00:00-01:00:00.log", "2024-04-29/open_http.00:00:00-01:00:00.log", "2024-04-29/ssl.00:00:00-01:00:00.log", "2024-04-29/open_ssl.00:00:00-01:00:00.log"},
						{"2024-04-29/conn.23:00:00-00:00:00.log", "2024-04-29/open_conn.23:00:00-00:00:00.log", "2024-04-29/dns.23:00:00-00:00:00.log", "2024-04-29/http.23:00:00-00:00:00.log", "2024-04-29/open_http.23:00:00-00:00:00.log", "2024-04-29/ssl.23:00:00-00:00:00.log", "2024-04-29/open_ssl.23:00:00-00:00:00.log"},
						{"2024-05-01/conn.00:00:00-01:00:00.log", "2024-05-01/open_conn.00:00:00-01:00:00.log", "2024-05-01/dns.00:00:00-01:00:00.log", "2024-05-01/http.00:00:00-01:00:00.log", "2024-05-01/open_http.00:00:00-01:00:00.log", "2024-05-01/ssl.00:00:00-01:00:00.log", "2024-05-01/open_ssl.00:00:00-01:00:00.log"},
						{"2024-05-01/conn.23:00:00-00:00:00.log", "2024-05-01/open_conn.23:00:00-00:00:00.log", "2024-05-01/dns.23:00:00-00:00:00.log", "2024-05-01/http.23:00:00-00:00:00.log", "2024-05-01/open_http.23:00:00-00:00:00.log", "2024-05-01/ssl.23:00:00-00:00:00.log", "2024-05-01/open_ssl.23:00:00-00:00:00.log", "2024-05-01/ssl_blue.23:00:00-00:00:00.log"},
					},
					rolling:        false,
					rebuild:        false,
					expectedImport: 4,
					expectedError:  nil,
				},
			},
		},

		{
			name: "SubDirectories, Multi-Day, Multi-Hour Logs",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs",
					hours: [][]string{
						{"2024-04-29/conn.00:00:00-01:00:00.log", "2024-04-29/open_conn.00:00:00-01:00:00.log", "2024-04-29/dns.00:00:00-01:00:00.log", "2024-04-29/http.00:00:00-01:00:00.log", "2024-04-29/open_http.00:00:00-01:00:00.log", "2024-04-29/ssl.00:00:00-01:00:00.log", "2024-04-29/open_ssl.00:00:00-01:00:00.log"},
						{"2024-04-29/conn.23:00:00-00:00:00.log", "2024-04-29/open_conn.23:00:00-00:00:00.log", "2024-04-29/dns.23:00:00-00:00:00.log", "2024-04-29/http.23:00:00-00:00:00.log", "2024-04-29/open_http.23:00:00-00:00:00.log", "2024-04-29/ssl.23:00:00-00:00:00.log", "2024-04-29/open_ssl.23:00:00-00:00:00.log"},
						{"2024-05-01/conn.00:00:00-01:00:00.log", "2024-05-01/open_conn.00:00:00-01:00:00.log", "2024-05-01/dns.00:00:00-01:00:00.log", "2024-05-01/http.00:00:00-01:00:00.log", "2024-05-01/open_http.00:00:00-01:00:00.log", "2024-05-01/ssl.00:00:00-01:00:00.log", "2024-05-01/open_ssl.00:00:00-01:00:00.log"},
						{"2024-05-01/conn.23:00:00-00:00:00.log", "2024-05-01/open_conn.23:00:00-00:00:00.log", "2024-05-01/dns.23:00:00-00:00:00.log", "2024-05-01/http.23:00:00-00:00:00.log", "2024-05-01/open_http.23:00:00-00:00:00.log", "2024-05-01/ssl.23:00:00-00:00:00.log", "2024-05-01/open_ssl.23:00:00-00:00:00.log", "2024-05-01/ssl_blue.23:00:00-00:00:00.log"},
					},
					rolling:        false,
					rebuild:        false,
					expectedImport: 4,
					expectedError:  nil,
				},
			},
		},
		{
			name: "Rolling",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs/1",
					hours: [][]string{
						{"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 1,
					expectedError:  nil,
				},
				{
					name:   "bingbong",
					logDir: "/logs/2",
					hours: [][]string{
						{"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 1,
					expectedError:  nil,
				},
			},
		},
		{
			name: "Rolling - Multi-Day, Multi-Hour Logs",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs/1",
					hours: [][]string{
						{"2024-04-29/conn.00:00:00-01:00:00.log", "2024-04-29/open_conn.00:00:00-01:00:00.log", "2024-04-29/dns.00:00:00-01:00:00.log", "2024-04-29/http.00:00:00-01:00:00.log", "2024-04-29/open_http.00:00:00-01:00:00.log", "2024-04-29/ssl.00:00:00-01:00:00.log", "2024-04-29/open_ssl.00:00:00-01:00:00.log"},
						{"2024-04-29/conn.23:00:00-00:00:00.log", "2024-04-29/open_conn.23:00:00-00:00:00.log", "2024-04-29/dns.23:00:00-00:00:00.log", "2024-04-29/http.23:00:00-00:00:00.log", "2024-04-29/open_http.23:00:00-00:00:00.log", "2024-04-29/ssl.23:00:00-00:00:00.log", "2024-04-29/open_ssl.23:00:00-00:00:00.log"},
						{"2024-05-01/conn.00:00:00-01:00:00.log", "2024-05-01/open_conn.00:00:00-01:00:00.log", "2024-05-01/dns.00:00:00-01:00:00.log", "2024-05-01/http.00:00:00-01:00:00.log", "2024-05-01/open_http.00:00:00-01:00:00.log", "2024-05-01/ssl.00:00:00-01:00:00.log", "2024-05-01/open_ssl.00:00:00-01:00:00.log"},
						{"2024-05-01/conn.23:00:00-00:00:00.log", "2024-05-01/open_conn.23:00:00-00:00:00.log", "2024-05-01/dns.23:00:00-00:00:00.log", "2024-05-01/http.23:00:00-00:00:00.log", "2024-05-01/open_http.23:00:00-00:00:00.log", "2024-05-01/ssl.23:00:00-00:00:00.log", "2024-05-01/open_ssl.23:00:00-00:00:00.log", "2024-05-01/ssl_blue.23:00:00-00:00:00.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 4,
					expectedError:  nil,
				},
				{
					name:   "bingbong",
					logDir: "/logs/2",
					hours: [][]string{
						{"2024-05-02/conn.00:00:00-01:00:00.log", "2024-05-02/open_conn.00:00:00-01:00:00.log", "2024-05-02/dns.00:00:00-01:00:00.log", "2024-05-02/http.00:00:00-01:00:00.log", "2024-05-02/open_http.00:00:00-01:00:00.log", "2024-05-02/ssl.00:00:00-01:00:00.log", "2024-05-02/open_ssl.00:00:00-01:00:00.log"},
						{"2024-05-02/conn.23:00:00-00:00:00.log", "2024-05-02/open_conn.23:00:00-00:00:00.log", "2024-05-02/dns.23:00:00-00:00:00.log", "2024-05-02/http.23:00:00-00:00:00.log", "2024-05-02/open_http.23:00:00-00:00:00.log", "2024-05-02/ssl.23:00:00-00:00:00.log", "2024-05-02/open_ssl.23:00:00-00:00:00.log"},
						{"2024-05-03/conn.00:00:00-01:00:00.log", "2024-05-03/open_conn.00:00:00-01:00:00.log", "2024-05-03/dns.00:00:00-01:00:00.log", "2024-05-03/http.00:00:00-01:00:00.log", "2024-05-03/open_http.00:00:00-01:00:00.log", "2024-05-03/ssl.00:00:00-01:00:00.log", "2024-05-03/open_ssl.00:00:00-01:00:00.log"},
						{"2024-05-03/conn.23:00:00-00:00:00.log", "2024-05-03/open_conn.23:00:00-00:00:00.log", "2024-05-03/dns.23:00:00-00:00:00.log", "2024-05-03/http.23:00:00-00:00:00.log", "2024-05-03/open_http.23:00:00-00:00:00.log", "2024-05-03/ssl.23:00:00-00:00:00.log", "2024-05-03/open_ssl.23:00:00-00:00:00.log", "2024-05-03/ssl_blue.23:00:00-00:00:00.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 4,
					expectedError:  nil,
				},
			},
		},
		{
			name: "Files Previously Imported",
			afs:  afero.NewMemMapFs(),
			importDBs: []importDB{
				{
					name:   "bingbong",
					logDir: "/logs/1",
					hours: [][]string{
						{"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 1,
					expectedError:  nil,
				},
				{
					name:   "bingbong",
					logDir: "/logs/1",
					hours: [][]string{
						{"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log"},
					},
					rolling:        true,
					rebuild:        false,
					expectedImport: 1,
					expectedError:  importer.ErrAllFilesPreviouslyImported,
				},
			},
		},
	}

	for _, tc := range testCases {
		c.Run(tc.name, func() {
			t := c.T()

			// loop over each importDB
			for _, db := range tc.importDBs {
				// get start time
				importStartedAt := time.Now()

				var files []string
				var fullPathHours [][]string

				// get the root directory path
				fullRootDir := db.logDir

				// if we are using the real logs directory, we need to get the real full path
				if !strings.HasPrefix(db.logDir, "/logs") {
					// get the current working directory
					cwd, err := os.Getwd()
					if err != nil {
						fmt.Println("Error getting current working directory:", err)
						return
					}

					fullRootDir = filepath.Join(cwd, db.logDir)
				}

				// iterate over each day of logs
				for _, day := range db.hours {
					// append all the files to a single list for creation
					files = append(files, day...)

					// convert the day list of files to full path versions
					var fullHourFiles []string
					for _, file := range day {
						fullPath := filepath.Join(fullRootDir, file)
						fullHourFiles = append(fullHourFiles, fullPath)
					}
					fullPathHours = append(fullPathHours, fullHourFiles)
				}

				// if we are using the mock directory, we need to create it along with the files
				if strings.HasPrefix(db.logDir, "/logs") {
					// create mock directory
					err := tc.afs.MkdirAll(db.logDir, os.FileMode(0o775))
					require.NoError(t, err, "creating directory should not produce an error")
					// create mock files
					createMockZeekConnLogs(t, tc.afs, db.logDir, files, true)
				}

				// run the import command
				importResults, err := cmd.RunImportCmd(importStartedAt, c.cfg, tc.afs, db.logDir, db.name, db.rolling, db.rebuild)

				// check if we expect an error
				if db.expectedError != nil {
					require.Error(t, err, "running import command should produce an error")
					require.Contains(t, err.Error(), db.expectedError.Error(), "error should contain expected value")
					continue
				}

				// if no error was expected, continue with the rest of the checks
				require.NoError(t, err, "running import command should not produce an error")
				require.NotNil(t, importResults, "import results should not be nil")

				// verify the number of import IDs
				require.Len(t, importResults.ImportID, db.expectedImport, "import results should have expected number of import IDs")

				// check if the database exists
				exists, err := database.SensorDatabaseExists(context.Background(), c.server.Conn, db.name)
				require.NoError(t, err, "checking if sensor database exists should not produce an error")
				require.True(t, exists, "sensor database should exist")

				// check rolling status
				isRolling, err := database.GetRollingStatus(context.Background(), c.server.Conn, db.name)
				require.NoError(t, err, "checking if sensor database is rolling should not produce an error")
				require.Equal(t, db.rolling, isRolling, "rolling status should match expected value")

				// verify imported paths for each hour
				for i := range fullPathHours {
					var result struct {
						Paths []string `ch:"paths"`
					}

					ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
						"import_id": importResults.ImportID[i].Hex(),
						"database":  db.name,
					}))

					err = c.server.Conn.QueryRow(ctx, `
					SELECT groupArray(path) AS paths
					FROM metadatabase.files
					WHERE import_id = unhex({import_id:String}) AND database = {database:String}
				`).ScanStruct(&result)
					require.NoError(t, err, "querying for total file count should not produce an error")

					require.ElementsMatch(t, fullPathHours[i], result.Paths, "paths should match expected value")
				}

			}

			// cleanup each importDB
			for _, db := range tc.importDBs {
				// clean up the directory if we are using a mock directory
				// if tc.logDir == "/logs" {
				if strings.HasPrefix(db.logDir, "/logs") {
					require.NoError(t, tc.afs.RemoveAll(db.logDir), "removing directory should not produce an error")
				}

				// clean up the database
				err := c.server.DeleteSensorDB(db.name)
				require.NoError(t, err, "dropping database should not produce an error")

			}
		})
	}

}

func (c *CmdTestSuite) TestRollingLogsBeingAddedToSameFolder() {
	t := c.T()

	type importCase struct {
		connLogs     []string
		dnsLogs      []string
		httpLogs     []string
		sslLogs      []string
		openConnLogs []string
	}

	testCases := []struct {
		name          string
		cases         []importCase
		expectedError error
	}{
		{
			name: "Same Folder Non Hour",
			cases: []importCase{
				{
					connLogs: []string{"conn.log"},
				},
				{
					dnsLogs: []string{"dns.log"},
				},
			},
		},
		{
			name: "Same Folder - Hour",
			cases: []importCase{
				{
					connLogs: []string{"conn.00:00:00-01:00:00.log"},
					dnsLogs:  []string{"dns.00:00:00-01:00:00.log"},
					httpLogs: []string{"http.00:00:00-01:10:00.log"},
					sslLogs:  []string{"ssl.00:00:00-01:10:00.log"},
				},
				{
					connLogs: []string{"conn.01:00:00-02:00:00.log"},
					dnsLogs:  []string{"dns.01:00:00-02:00:00.log"},
					httpLogs: []string{"http.01:00:00-02:50:00.log"},
					sslLogs:  []string{"ssl.01:00:00-02:10:00.log"},
				},
			},
		},
		{
			name: "Subfolders - One Has Non Imported",
			cases: []importCase{
				{
					connLogs: []string{"conn.log", "/subfolder/conn.log"},
					dnsLogs:  []string{"dns.log", "/subfolder/dns.log"},
					httpLogs: []string{"http.log", "/subfolder/http.log"},
					sslLogs:  []string{"ssl.log", "/subfolder/ssl.log"},
				},
				{
					connLogs: []string{"/subfolder2/conn.log"},
					dnsLogs:  []string{"/subfolder2/dns.log"},
					httpLogs: []string{"/subfolder2/http.log"},
					sslLogs:  []string{"/subfolder2/ssl.log"},
				},
			},
		},
		{
			name: "Subfolders - Both Have Non Imported",
			cases: []importCase{
				{
					connLogs: []string{"conn.log"},
					dnsLogs:  []string{"dns.log"},
					httpLogs: []string{"http.log"},
					sslLogs:  []string{"ssl.log"},
				},
				{
					connLogs: []string{"/subfolder/conn.log", "/subfolder2/conn.log"},
					dnsLogs:  []string{"/subfolder/conn.log", "/subfolder2/dns.log"},
					httpLogs: []string{"/subfolder/conn.log", "/subfolder2/http.log"},
					sslLogs:  []string{"/subfolder/conn.log", "/subfolder2/ssl.log"},
				},
			},
		},
		{
			name: "Subfolders - All Have Non Imported",
			cases: []importCase{
				{
					connLogs: []string{"conn.log"},
					dnsLogs:  []string{"dns.log"},
					httpLogs: []string{"http.log"},
					sslLogs:  []string{"ssl.log"},
				},
				{
					connLogs: []string{"conn.00:00:00-01:00:00.log", "/subfolder/conn.log", "/subfolder2/conn.log"},
					dnsLogs:  []string{"dns.03:00:00-04:00:00.log", "/subfolder/dns.log", "/subfolder2/dns.log"},
					httpLogs: []string{"http.00:00:00-01:00:00.log", "/subfolder/http.log", "/subfolder2/http.log"},
					sslLogs:  []string{"ssl.00:00:00-01:00:00.log", "/subfolder/ssl.log", "/subfolder2/ssl.log"},
				},
			},
		},
		{
			name: "Subfolders - All Previously Imported",
			cases: []importCase{
				{
					connLogs: []string{"conn.00:00:00-01:00:00.log", "/subfolder/conn.log", "/subfolder2/conn.log"},
					dnsLogs:  []string{"dns.03:00:00-04:00:00.log", "/subfolder/dns.log", "/subfolder2/dns.log"},
					httpLogs: []string{"http.00:00:00-01:00:00.log", "/subfolder/http.log", "/subfolder2/http.log"},
					sslLogs:  []string{"ssl.00:00:00-01:00:00.log", "/subfolder/ssl.log", "/subfolder2/ssl.log"},
				},
				{
					connLogs: []string{"conn.00:00:00-01:00:00.log", "/subfolder/conn.log", "/subfolder2/conn.log"},
					dnsLogs:  []string{"dns.03:00:00-04:00:00.log", "/subfolder/dns.log", "/subfolder2/dns.log"},
					httpLogs: []string{"http.00:00:00-01:00:00.log", "/subfolder/http.log", "/subfolder2/http.log"},
					sslLogs:  []string{"ssl.00:00:00-01:00:00.log", "/subfolder/ssl.log", "/subfolder2/ssl.log"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			afs := afero.NewMemMapFs()
			err := afs.MkdirAll("/logs", 0o755)
			require.NoError(t, err)

			for hour, importCase := range tc.cases {
				// create conn files
				createMockZeekConnLogs(t, afs, "/logs", importCase.connLogs, true)
				createMockZeekProtoLogs(t, afs, "/logs", importCase.dnsLogs, true, "query")
				createMockZeekConnLogs(t, afs, "/logs", importCase.openConnLogs, true)
				createMockZeekProtoLogs(t, afs, "/logs", importCase.httpLogs, true, "host")
				createMockZeekProtoLogs(t, afs, "/logs", importCase.sslLogs, true, "server_name")

				results, err := cmd.RunImportCmd(time.Now(), c.cfg, afs, "/logs", "test_rolling_same_folder", true, true)

				// check if we expect an error
				if tc.expectedError != nil {
					require.Error(t, err, "running import command should produce an error")
					require.Contains(t, err.Error(), tc.expectedError.Error(), "error should contain expected value")
				} else {
					require.NoError(t, err, "running import command should not produce an error")

					if len(importCase.connLogs) > 0 {
						require.Greater(t, results.ResultCounts.Conn, uint64(0), "hour %d: conn logs should be imported", hour)
					}

					if len(importCase.dnsLogs) > 0 {
						require.Greater(t, results.ResultCounts.DNS, uint64(0), "hour %d: dns logs should be imported", hour)
					}

					if len(importCase.httpLogs) > 0 {
						require.Greater(t, results.ResultCounts.HTTP, uint64(0), "hour %d: http logs should be imported", hour)
					}

					if len(importCase.sslLogs) > 0 {
						require.Greater(t, results.ResultCounts.SSL, uint64(0), "hour %d: ssl logs should be imported", hour)
					}

					if len(importCase.openConnLogs) > 0 {
						require.Greater(t, results.ResultCounts.OpenConn, uint64(0), "hour %d: open conn logs should be imported", hour)
					}

				}

			}

			require.NoError(t, afs.RemoveAll("/logs"), "removing directory should not produce an error")

			// clean up the database
			require.NoError(t, c.server.DeleteSensorDB("test_rolling_same_folder"), "dropping database should not produce an error")
		})
	}

}

// createMockZeekConnLogs creates a directory with files that contain mock Zeek logs, filling them with valid
// log values if necessary for the test
func createMockZeekConnLogs(t *testing.T, afs afero.Fs, directory string, files []string, valid bool) {
	t.Helper()

	// create files
	for _, file := range files {
		data := []byte("test")
		if valid {
			data = []byte("#separator \\x09\n" +
				"#set_separator\t,\n" +
				"#empty_field\t(empty)\n" +
				"#unset_field\t-\n" +
				"#path\tconn\n" +
				"#open\t2019-02-28-12-07-01\n" +
				"#fields\tts\tuid\tid.orig_h\tid.resp_h\n" +
				"#types\ttime\tstring\taddr\taddr\n" +
				"1715640994.367201\tCxT121\t10.0.0.1\t52.12.0.1\n" +
				"1715640994.367201\tCxT121\t10.0.0.1\t52.12.0.1\n" +
				"1715641054.367201\tCxT122\t10.0.0.2\t52.12.0.2\n" +
				"1715641054.367201\tCxT122\t10.0.0.2\t52.12.0.2\n" +
				"1715641114.367201\tCxT123\t10.0.0.3\t52.12.0.3\n" +
				"1715641114.367201\tCxT123\t10.0.0.3\t52.12.0.3\n" +
				"1715641174.367201\tCxT124\t10.0.0.4\t52.12.0.4\n" +
				"1715641174.367201\tCxT124\t10.0.0.4\t52.12.0.4\n" +
				"1715641234.367201\tCxT125\t10.0.0.5\t52.12.0.5\n" +
				"1715641234.367201\tCxT125\t10.0.0.5\t52.12.0.5\n",
			)
		}
		err := afero.WriteFile(afs, filepath.Join(directory, file), data, os.FileMode(0o775))
		require.NoError(t, err, "creating files should not produce an error")
	}
}

func createMockZeekProtoLogs(t *testing.T, afs afero.Fs, directory string, files []string, valid bool, field string) {
	t.Helper()

	// create files
	for _, file := range files {
		data := []byte("test")
		if valid {
			data = []byte("#separator \\x09\n" +
				"#set_separator\t,\n" +
				"#empty_field\t(empty)\n" +
				"#unset_field\t-\n" +
				"#path\tdns\n" +
				"#open\t2019-02-28-12-07-01\n" +
				"#fields\tts\tuid\tid.orig_h\tid.resp_h\t" + field + "\n" +
				"#types\ttime\tstring\taddr\taddr\tstring\n" +
				"1715640994.367201\tCxT121\t10.0.0.1\t52.12.0.1\tmicrosoft.com\n" +
				"1715640994.367201\tCxT121\t10.0.0.1\t52.12.0.1\ta.microsoft.com\n" +
				"1715641054.367201\tCxT122\t10.0.0.2\t52.12.0.2\tgoogle.com\n" +
				"1715641054.367201\tCxT122\t10.0.0.2\t52.12.0.2\tyahoo.com\n" +
				"1715641114.367201\tCxT123\t10.0.0.3\t52.12.0.3\ttime.apple.com\n" +
				"1715641114.367201\tCxT123\t10.0.0.3\t52.12.0.3\treddit.com\n" +
				"1715641174.367201\tCxT124\t10.0.0.4\t52.12.0.4\tnasa.org\n" +
				"1715641174.367201\tCxT124\t10.0.0.4\t52.12.0.4\tyoutube.com\n" +
				"1715641234.367201\tCxT125\t10.0.0.5\t52.12.0.5\ttwitch.tv\n" +
				"1715641234.367201\tCxT125\t10.0.0.5\t52.12.0.5\tmaps.google.com\n",
			)
		}
		err := afero.WriteFile(afs, filepath.Join(directory, file), data, os.FileMode(0o775))
		require.NoError(t, err, "creating files should not produce an error")
	}
}

func createExpectedResults(logs []cmd.HourlyZeekLogs) []cmd.HourlyZeekLogs {
	var data []cmd.HourlyZeekLogs

	// create 24 hours for each day defined in test
	for range logs {
		hourly := make(cmd.HourlyZeekLogs, 24)
		data = append(data, hourly)
	}

	// override the empty data structure with the test data
	for i, day := range logs {
		for j, hour := range day {
			for logPrefix, logPaths := range hour {
				// initialize map if the test data has data for that hour
				if data[i][j] == nil {
					data[i][j] = make(map[string][]string)
				}
				data[i][j][logPrefix] = logPaths
			}
		}
	}
	return data
}

func TestWalkFiles(t *testing.T) {

	tests := []struct {
		name                 string
		directory            string
		directoryPermissions iofs.FileMode
		filePermissions      iofs.FileMode
		subdirectories       []string
		files                []string
		expectedFiles        []cmd.HourlyZeekLogs
		expectedWalkErrors   []cmd.WalkError
		rolling              bool
		expectedError        error
	}{
		{
			name:                 "Valid Non-Hour Logs",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log",
				"conn_red.log", "dns_red.log", "http_red.log", "ssl_red.log",
				"conn_blue.log.gz", "dns_blue.log.gz", "http_blue.log.gz", "ssl_blue.log.gz",
				".DS_STORE", "capture_loss.16:00:00-17:00:00.log.gz", "stats.16:00:00-17:00:00.log.gz", "x509.16:00:00-17:00:00.log.gz",
				"known_certs.16:00:00-17:00:00.log.gz",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix:     []string{"/logs/conn.log", "/logs/conn_blue.log.gz", "/logs/conn_red.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.log"},
						constants.DNSPrefix:      []string{"/logs/dns.log", "/logs/dns_blue.log.gz", "/logs/dns_red.log"},
						constants.HTTPPrefix:     []string{"/logs/http.log", "/logs/http_blue.log.gz", "/logs/http_red.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.log", "/logs/ssl_blue.log.gz", "/logs/ssl_red.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.log"},
					},
				},
			}),
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs/.DS_STORE", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/capture_loss.16:00:00-17:00:00.log.gz", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/stats.16:00:00-17:00:00.log.gz", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/x509.16:00:00-17:00:00.log.gz", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/known_certs.16:00:00-17:00:00.log.gz", Error: cmd.ErrInvalidLogType},
			},
			expectedError: nil,
		},
		{
			name:                 "Hour Logs, Format 00:00:00",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				"conn.00:00:00-01:00:00.log", "conn_red.00:00:00-01:00:00.log", "conn_blue.00:00:00-01:00:00.log.gz", "open_conn.00:00:00-01:00:00.log",
				"dns.00:00:00-01:00:00.log", "dns_red.00:00:00-01:00:00.log", "dns_blue.00:00:00-01:00:00.log.gz",
				"http.00:00:00-01:00:00.log", "http_red.00:00:00-01:00:00.log", "http_blue.00:00:00-01:00:00.log.gz", "open_http.00:00:00-01:00:00.log",
				"ssl.00:00:00-01:00:00.log", "ssl_red.00:00:00-01:00:00.log", "ssl_blue.00:00:00-01:00:00.log.gz", "open_ssl.00:00:00-01:00:00.log",

				"conn.01:00:00-02:00:00.log", "conn_red.01:00:00-02:00:00.log", "conn_blue.01:00:00-02:00:00.log.gz", "open_conn.01:00:00-02:00:00.log",
				"dns.01:00:00-02:00:00.log", "dns_red.01:00:00-02:00:00.log", "dns_blue.01:00:00-02:00:00.log.gz",
				"http.01:00:00-02:00:00.log", "http_red.01:00:00-02:00:00.log", "http_blue.01:00:00-02:00:00.log.gz", "open_http.01:00:00-02:00:00.log",
				"ssl.01:00:00-02:00:00.log", "ssl_red.01:00:00-02:00:00.log", "ssl_blue.01:00:00-02:00:00.log.gz", "open_ssl.01:00:00-02:00:00.log",

				"conn.22:00:00-23:00:00.log", "conn_red.22:00:00-23:00:00.log", "conn_blue.22:00:00-23:00:00.log.gz", "open_conn.22:00:00-23:00:00.log",
				"dns.22:00:00-23:00:00.log", "dns_red.22:00:00-23:00:00.log", "dns_blue.22:00:00-23:00:00.log.gz",
				"http.22:00:00-23:00:00.log", "http_red.22:00:00-23:00:00.log", "http_blue.22:00:00-23:00:00.log.gz", "open_http.22:00:00-23:00:00.log",
				"ssl.22:00:00-23:00:00.log", "ssl_red.22:00:00-23:00:00.log", "ssl_blue.22:00:00-23:00:00.log.gz", "open_ssl.22:00:00-23:00:00.log",

				"conn.23:00:00-00:00:00.log", "conn_red.23:00:00-00:00:00.log", "conn_blue.23:00:00-00:00:00.log.gz", "open_conn.23:00:00-00:00:00.log",
				"dns.23:00:00-00:00:00.log", "dns_red.23:00:00-00:00:00.log", "dns_blue.23:00:00-00:00:00.log.gz",
				"http.23:00:00-00:00:00.log", "http_red.23:00:00-00:00:00.log", "http_blue.23:00:00-00:00:00.log.gz", "open_http.23:00:00-00:00:00.log",
				"ssl.23:00:00-00:00:00.log", "ssl_red.23:00:00-00:00:00.log", "ssl_blue.23:00:00-00:00:00.log.gz", "open_ssl.23:00:00-00:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix:     []string{"/logs/conn.00:00:00-01:00:00.log", "/logs/conn_blue.00:00:00-01:00:00.log.gz", "/logs/conn_red.00:00:00-01:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.00:00:00-01:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/dns.00:00:00-01:00:00.log", "/logs/dns_blue.00:00:00-01:00:00.log.gz", "/logs/dns_red.00:00:00-01:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/http.00:00:00-01:00:00.log", "/logs/http_blue.00:00:00-01:00:00.log.gz", "/logs/http_red.00:00:00-01:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.00:00:00-01:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.00:00:00-01:00:00.log", "/logs/ssl_blue.00:00:00-01:00:00.log.gz", "/logs/ssl_red.00:00:00-01:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.00:00:00-01:00:00.log"},
					},
					1: {
						constants.ConnPrefix:     []string{"/logs/conn.01:00:00-02:00:00.log", "/logs/conn_blue.01:00:00-02:00:00.log.gz", "/logs/conn_red.01:00:00-02:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.01:00:00-02:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/dns.01:00:00-02:00:00.log", "/logs/dns_blue.01:00:00-02:00:00.log.gz", "/logs/dns_red.01:00:00-02:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/http.01:00:00-02:00:00.log", "/logs/http_blue.01:00:00-02:00:00.log.gz", "/logs/http_red.01:00:00-02:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.01:00:00-02:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.01:00:00-02:00:00.log", "/logs/ssl_blue.01:00:00-02:00:00.log.gz", "/logs/ssl_red.01:00:00-02:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.01:00:00-02:00:00.log"},
					},
					22: {
						constants.ConnPrefix:     []string{"/logs/conn.22:00:00-23:00:00.log", "/logs/conn_blue.22:00:00-23:00:00.log.gz", "/logs/conn_red.22:00:00-23:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.22:00:00-23:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/dns.22:00:00-23:00:00.log", "/logs/dns_blue.22:00:00-23:00:00.log.gz", "/logs/dns_red.22:00:00-23:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/http.22:00:00-23:00:00.log", "/logs/http_blue.22:00:00-23:00:00.log.gz", "/logs/http_red.22:00:00-23:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.22:00:00-23:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.22:00:00-23:00:00.log", "/logs/ssl_blue.22:00:00-23:00:00.log.gz", "/logs/ssl_red.22:00:00-23:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.22:00:00-23:00:00.log"},
					},
					23: {
						constants.ConnPrefix:     []string{"/logs/conn.23:00:00-00:00:00.log", "/logs/conn_blue.23:00:00-00:00:00.log.gz", "/logs/conn_red.23:00:00-00:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.23:00:00-00:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/dns.23:00:00-00:00:00.log", "/logs/dns_blue.23:00:00-00:00:00.log.gz", "/logs/dns_red.23:00:00-00:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/http.23:00:00-00:00:00.log", "/logs/http_blue.23:00:00-00:00:00.log.gz", "/logs/http_red.23:00:00-00:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.23:00:00-00:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.23:00:00-00:00:00.log", "/logs/ssl_blue.23:00:00-00:00:00.log.gz", "/logs/ssl_red.23:00:00-00:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.23:00:00-00:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Hour Logs, Containing all Log Types",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				// all logs
				"conn.01:00:00-02:00:00.log", "open_conn.01:00:00-02:00:00.log", "dns.01:00:00-02:00:00.log", "http.01:00:00-02:00:00.log", "open_http.01:00:00-02:00:00.log", "ssl.01:00:00-02:00:00.log", "open_ssl.01:00:00-02:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					1: {
						constants.ConnPrefix:     []string{"/logs/conn.01:00:00-02:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.01:00:00-02:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/dns.01:00:00-02:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/http.01:00:00-02:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.01:00:00-02:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.01:00:00-02:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.01:00:00-02:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Hour Logs, Containing all Log Types - Corelight Format",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				"conn_red.00:00:00-01:00:00.log",
				"conn_20240722_12:00:00-13:00:00+0000.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix: []string{
							"/logs/conn_red.00:00:00-01:00:00.log",
						},
					},
					12: {
						constants.ConnPrefix: []string{
							"/logs/conn_20240722_12:00:00-13:00:00+0000.log",
						},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Hour Logs, Missing conn & open_conn Logs",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				// missing conn and open conn
				"dns.00:00:00-01:00:00.log", "http.00:00:00-01:00:00.log", "open_http.00:00:00-01:00:00.log", "ssl.00:00:00-01:00:00.log", "open_ssl.00:00:00-01:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.DNSPrefix: []string{"/logs/dns.00:00:00-01:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},

		{
			name:                 "Hour Logs, Missing conn, has open_conn",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				// missing conn, has open conn
				"open_conn.02:00:00-03:00:00.log", "dns.02:00:00-03:00:00.log", "http.02:00:00-03:00:00.log", "open_http.02:00:00-03:00:00.log", "ssl.02:00:00-03:00:00.log", "open_ssl.02:00:00-03:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					2: {
						"open_conn": []string{"/logs/open_conn.02:00:00-03:00:00.log"},
						"dns":       []string{"/logs/dns.02:00:00-03:00:00.log"},
						"open_http": []string{"/logs/open_http.02:00:00-03:00:00.log"},
						"open_ssl":  []string{"/logs/open_ssl.02:00:00-03:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Hour Logs, Missing open_conn, has conn",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				// missing open conn, has conn
				"conn.22:00:00-23:00:00.log", "dns.22:00:00-23:00:00.log", "http.22:00:00-23:00:00.log", "ssl.22:00:00-23:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					22: {
						constants.ConnPrefix: []string{"/logs/conn.22:00:00-23:00:00.log"},
						constants.DNSPrefix:  []string{"/logs/dns.22:00:00-23:00:00.log"},
						constants.HTTPPrefix: []string{"/logs/http.22:00:00-23:00:00.log"},
						constants.SSLPrefix:  []string{"/logs/ssl.22:00:00-23:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Hour Logs, Missing open_conn, conn, and dns",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				// missing open conn, conn, and dns
				"http.23:00:00-00:00:00.log", "ssl.23:00:00-00:00:00.log", "open_http.23:00:00-00:00:00.log", "open_ssl.23:00:00-00:00:00.log",
			},
			expectedWalkErrors: nil,
			expectedError:      cmd.ErrNoValidFilesFound, // TODO: error for missing conn, open_conn, and dns
		},
		{
			name:                 "SubDirectories - Non-Hour Logs",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			// subdirectories:       []string{"/sensor1", "/sensor2"},
			files: []string{
				"sensor1/conn.log", "sensor1/dns.log", "sensor1/http.log", "sensor1/ssl.log", "sensor1/open_conn.log", "sensor1/open_http.log", "sensor1/open_ssl.log",
				"sensor2/conn.log", "sensor2/dns.log", "sensor2/http.log", "sensor2/ssl.log", "sensor2/open_conn.log", "sensor2/open_http.log", "sensor2/open_ssl.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix:     []string{"/logs/sensor1/conn.log", "/logs/sensor2/conn.log"},
						constants.OpenConnPrefix: []string{"/logs/sensor1/open_conn.log", "/logs/sensor2/open_conn.log"},
						constants.DNSPrefix:      []string{"/logs/sensor1/dns.log", "/logs/sensor2/dns.log"},
						constants.HTTPPrefix:     []string{"/logs/sensor1/http.log", "/logs/sensor2/http.log"},
						constants.OpenHTTPPrefix: []string{"/logs/sensor1/open_http.log", "/logs/sensor2/open_http.log"},
						constants.SSLPrefix:      []string{"/logs/sensor1/ssl.log", "/logs/sensor2/ssl.log"},
						constants.OpenSSLPrefix:  []string{"/logs/sensor1/open_ssl.log", "/logs/sensor2/open_ssl.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "SubDirectories - Hour Logs",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			subdirectories:       []string{"/sensor1", "/sensor2"},
			files: []string{
				"sensor1/conn.00:00:00-01:00:00.log", "sensor1/open_conn.00:00:00-01:00:00.log", "sensor1/dns.00:00:00-01:00:00.log", "sensor1/http.00:00:00-01:00:00.log", "sensor1/open_http.00:00:00-01:00:00.log", "sensor1/ssl.00:00:00-01:00:00.log", "sensor1/open_ssl.00:00:00-01:00:00.log",
				"sensor2/conn.00:00:00-01:00:00.log", "sensor2/open_conn.00:00:00-01:00:00.log", "sensor2/dns.00:00:00-01:00:00.log", "sensor2/http.00:00:00-01:00:00.log", "sensor2/open_http.00:00:00-01:00:00.log", "sensor2/ssl.00:00:00-01:00:00.log", "sensor2/open_ssl.00:00:00-01:00:00.log",
				"sensor1/conn.23:00:00-00:00:00.log", "sensor1/open_conn.23:00:00-00:00:00.log", "sensor1/dns.23:00:00-00:00:00.log", "sensor1/http.23:00:00-00:00:00.log", "sensor1/open_http.23:00:00-00:00:00.log", "sensor1/ssl.23:00:00-00:00:00.log", "sensor1/open_ssl.23:00:00-00:00:00.log",
				"sensor2/conn.23:00:00-00:00:00.log", "sensor2/open_conn.23:00:00-00:00:00.log", "sensor2/dns.23:00:00-00:00:00.log", "sensor2/http.23:00:00-00:00:00.log", "sensor2/open_http.23:00:00-00:00:00.log", "sensor2/ssl.23:00:00-00:00:00.log", "sensor2/open_ssl.23:00:00-00:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix:     []string{"/logs/sensor1/conn.00:00:00-01:00:00.log", "/logs/sensor2/conn.00:00:00-01:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/sensor1/open_conn.00:00:00-01:00:00.log", "/logs/sensor2/open_conn.00:00:00-01:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/sensor1/dns.00:00:00-01:00:00.log", "/logs/sensor2/dns.00:00:00-01:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/sensor1/http.00:00:00-01:00:00.log", "/logs/sensor2/http.00:00:00-01:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/sensor1/open_http.00:00:00-01:00:00.log", "/logs/sensor2/open_http.00:00:00-01:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/sensor1/ssl.00:00:00-01:00:00.log", "/logs/sensor2/ssl.00:00:00-01:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/sensor1/open_ssl.00:00:00-01:00:00.log", "/logs/sensor2/open_ssl.00:00:00-01:00:00.log"},
					},
					23: {
						constants.ConnPrefix:     []string{"/logs/sensor1/conn.23:00:00-00:00:00.log", "/logs/sensor2/conn.23:00:00-00:00:00.log"},
						constants.OpenConnPrefix: []string{"/logs/sensor1/open_conn.23:00:00-00:00:00.log", "/logs/sensor2/open_conn.23:00:00-00:00:00.log"},
						constants.DNSPrefix:      []string{"/logs/sensor1/dns.23:00:00-00:00:00.log", "/logs/sensor2/dns.23:00:00-00:00:00.log"},
						constants.HTTPPrefix:     []string{"/logs/sensor1/http.23:00:00-00:00:00.log", "/logs/sensor2/http.23:00:00-00:00:00.log"},
						constants.OpenHTTPPrefix: []string{"/logs/sensor1/open_http.23:00:00-00:00:00.log", "/logs/sensor2/open_http.23:00:00-00:00:00.log"},
						constants.SSLPrefix:      []string{"/logs/sensor1/ssl.23:00:00-00:00:00.log", "/logs/sensor2/ssl.23:00:00-00:00:00.log"},
						constants.OpenSSLPrefix:  []string{"/logs/sensor1/open_ssl.23:00:00-00:00:00.log", "/logs/sensor2/open_ssl.23:00:00-00:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "SubDirectories - Multi-Day Logs",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			// subdirectories:       []string{"/2024-04-29", "/2024-05-01"},
			files: []string{
				"2024-04-29/conn.log", "2024-04-29/dns.log", "2024-04-29/http.log", "2024-04-29/ssl.log", "2024-04-29/open_conn.log", "2024-04-29/open_http.log", "2024-04-29/open_ssl.log",
				"2024-05-01/conn.log", "2024-05-01/dns.log", "2024-05-01/http.log", "2024-05-01/ssl.log", "2024-05-01/open_conn.log", "2024-05-01/open_http.log", "2024-05-01/open_ssl.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix:     []string{"/logs/2024-04-29/conn.log"},
						constants.OpenConnPrefix: []string{"/logs/2024-04-29/open_conn.log"},
						constants.DNSPrefix:      []string{"/logs/2024-04-29/dns.log"},
						constants.HTTPPrefix:     []string{"/logs/2024-04-29/http.log"},
						constants.OpenHTTPPrefix: []string{"/logs/2024-04-29/open_http.log"},
						constants.SSLPrefix:      []string{"/logs/2024-04-29/ssl.log"},
						constants.OpenSSLPrefix:  []string{"/logs/2024-04-29/open_ssl.log"},
					},
				},
				1: {
					0: {
						constants.ConnPrefix:     []string{"/logs/2024-05-01/conn.log"},
						constants.OpenConnPrefix: []string{"/logs/2024-05-01/open_conn.log"},
						constants.DNSPrefix:      []string{"/logs/2024-05-01/dns.log"},
						constants.HTTPPrefix:     []string{"/logs/2024-05-01/http.log"},
						constants.OpenHTTPPrefix: []string{"/logs/2024-05-01/open_http.log"},
						constants.SSLPrefix:      []string{"/logs/2024-05-01/ssl.log"},
						constants.OpenSSLPrefix:  []string{"/logs/2024-05-01/open_ssl.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},

		{
			name:                 "Non-Rolling, No Subdirectories",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files: []string{
				"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					{
						constants.ConnPrefix:     []string{"/logs/conn.log"},
						constants.OpenConnPrefix: []string{"/logs/open_conn.log"},
						constants.DNSPrefix:      []string{"/logs/dns.log"},
						constants.HTTPPrefix:     []string{"/logs/http.log"},
						constants.OpenHTTPPrefix: []string{"/logs/open_http.log"},
						constants.SSLPrefix:      []string{"/logs/ssl.log"},
						constants.OpenSSLPrefix:  []string{"/logs/open_ssl.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "All sorts of stuff",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			directory:            "/logs",
			// subdirectories:       []string{"/sensor1", "/2024-05-01"},
			files: []string{
				"2024-05-01/conn.log",
				"2024-05-01/dns.03:00:00-04:00:00.log",
				"dns.log",
				"dns.09:00:00-10:00:00.log",
				"sensor1/ssl.log",
				"sensor1/conn.log",
				"sensor1/2025-06-29/conn.04:00:00-05:00:00.log",
				"sensor1/2025-06-29/http.04:00:00-05:00:00.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{

				0: {
					0: {
						constants.DNSPrefix:  []string{"/logs/dns.log"},
						constants.SSLPrefix:  []string{"/logs/sensor1/ssl.log"},
						constants.ConnPrefix: []string{"/logs/sensor1/conn.log"},
					},
					9: {constants.DNSPrefix: []string{"/logs/dns.09:00:00-10:00:00.log"}},
				},
				1: {
					0: {constants.ConnPrefix: []string{"/logs/2024-05-01/conn.log"}},
					3: {constants.DNSPrefix: []string{"/logs/2024-05-01/dns.03:00:00-04:00:00.log"}},
				},
				2: {
					4: {
						constants.ConnPrefix: []string{"/logs/sensor1/2025-06-29/conn.04:00:00-05:00:00.log"},
						constants.HTTPPrefix: []string{"/logs/sensor1/2025-06-29/http.04:00:00-05:00:00.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},
		{
			name:                 "Single File Passed In as Root Directory",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			files:                []string{"open_conn.log"},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.OpenConnPrefix: []string{"open_conn.log"},
					},
				},
			}),
			expectedWalkErrors: nil,
			expectedError:      nil,
		},

		{
			name:                 "Duplicate Logs - Same Name, One Newer",
			directory:            "/logs_dupe",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			files: []string{
				"conn.log", "conn.log.gz",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix: []string{"/logs_dupe/conn.log.gz"},
					},
				},
			}),
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs_dupe/conn.log", Error: cmd.ErrSkippedDuplicateLog},
			},
			expectedError: nil,
		},
		{
			// checks the default case of the switch statement since the test above will be caught by the second case
			name:                 "Duplicate Logs - Same Name, One Newer - .log.gz File is Older",
			directory:            "/logs_dupe",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			files: []string{
				"conn.log.gz", "conn.log",
			},
			expectedFiles: createExpectedResults([]cmd.HourlyZeekLogs{
				0: {
					0: {
						constants.ConnPrefix: []string{"/logs_dupe/conn.log"},
					},
				},
			}),
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs_dupe/conn.log.gz", Error: cmd.ErrSkippedDuplicateLog},
			},
			expectedError: nil,
		},
		{
			name:                 "No Prefix on Files",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			files: []string{
				".log.gz", ".log", ".foo",
			},
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs/.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/.log.gz", Error: cmd.ErrSkippedDuplicateLog},
				{Path: "/logs/.foo", Error: cmd.ErrIncompatibleFileExtension},
			},
			expectedError: cmd.ErrNoValidFilesFound,
		},
		{
			name:                 "Incompatible or Missing File Extensions",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			files: []string{
				"conn", "dns", "http", "ssl", "open_conn", "open_http", "open_ssl", "conn.00:00:00-01:00:00",
				".conn", ".conn_", ".dns", ".dns_", ".http", ".http_", ".ssl", ".ssl_", ".bing", "._bong",
				"dns_file",
			},
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs/conn", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/dns", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/http", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/ssl", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/open_conn", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/open_http", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/open_ssl", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/conn.00:00:00-01:00:00", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.conn", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.conn_", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.dns", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.dns_", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.http", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.http_", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.ssl", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.ssl_", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/.bing", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/._bong", Error: cmd.ErrIncompatibleFileExtension},
				{Path: "/logs/dns_file", Error: cmd.ErrIncompatibleFileExtension},
			},
			expectedError: cmd.ErrNoValidFilesFound,
		},
		{
			name:                 "Invalid Log Types",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			files: []string{
				"files.log", "ntp.log", "radius.log", "sip.log", "x509.log.gz", "dhcp.log", "weird.log",
				"conn_summary.log", "conn-summary.log", "foo.log",
			},
			expectedWalkErrors: []cmd.WalkError{
				{Path: "/logs/files.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/ntp.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/radius.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/sip.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/x509.log.gz", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/dhcp.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/weird.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/conn_summary.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/conn-summary.log", Error: cmd.ErrInvalidLogType},
				{Path: "/logs/foo.log", Error: cmd.ErrInvalidLogType},
			},
			expectedError: cmd.ErrNoValidFilesFound,
		},

		// Previously, read permissions were checked with !(info.Mode().Perm()&0444 == 0444), but
		// this requires all read permissions (user, group, others)/0644 to be set which is not ideal.
		// A better check would be to see if any read permission is set, i.e., (info.Mode().Perm()&0444 != 0).
		// However, since some ACL systems/SELinux might interfere with this, it's better to let the Open() call
		// return an error if permission is denied.
		// Unfortunately, afero.MemMapFs does not support file permissions when using Open, so this test is skipped.
		// https://github.com/spf13/afero/issues/150
		// {
		// 	name:                 "No Read Permissions on Files",
		// 	directory:            "/logs",
		// 	directoryPermissions: iofs.FileMode(0o775),
		// 	filePermissions:      iofs.FileMode(0o000),
		// 	files: []string{
		// 		"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log",
		// 	},
		// 	expectedWalkErrors: []cmd.WalkError{
		// 		{Path: "/logs/conn.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/dns.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/http.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/ssl.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/open_conn.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/open_http.log", Error: cmd.ErrInsufficientReadPermissions},
		// 		{Path: "/logs/open_ssl.log", Error: cmd.ErrInsufficientReadPermissions},
		// 	},
		// 	expectedError: cmd.ErrNoValidFilesFound,
		// },
		{
			name:                 "No Files, Only SubDirectories",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			subdirectories:       []string{"/sensor1", "/sensor2"},
			expectedWalkErrors:   nil,
			expectedError:        cmd.ErrNoValidFilesFound,
		},
		{
			name:                 "No Files",
			directory:            "/logs",
			directoryPermissions: iofs.FileMode(0o775),
			filePermissions:      iofs.FileMode(0o775),
			expectedWalkErrors:   nil,
			expectedError:        util.ErrDirIsEmpty,
		},
		{
			name:                 "Rolling Logs - Old",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			rolling:              true,
			expectedWalkErrors:   nil,
			expectedError:        nil,
		},
		{
			name:                 "Rolling Logs - New",
			directory:            "/logs",
			directoryPermissions: os.FileMode(0o775),
			filePermissions:      os.FileMode(0o775),
			rolling:              true,
			expectedWalkErrors:   nil,
			expectedError:        nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// create a new in-memory filesystem for each test
			afs := afero.NewMemMapFs()

			// Create the directory
			if test.directory != "" {
				err := afs.MkdirAll(test.directory, test.directoryPermissions)
				require.NoError(t, err)
			}

			if !test.rolling {
				for _, subdirectory := range test.subdirectories {
					err := afs.MkdirAll(filepath.Join(test.directory, subdirectory), test.directoryPermissions)
					require.NoError(t, err)
				}
			} else {
				today := time.Now().UTC().Truncate(24 * time.Hour)
				files := []string{"conn.log", "dns.log", "http.log", "ssl.log", "open_conn.log", "open_http.log", "open_ssl.log"}
				switch test.name {
				case "Rolling Logs - Old":
					// test should keep all 11 days because none were in the past 2 weeks
					for i := -cmd.RollingLogDaysToKeep * 2; i < -cmd.RollingLogDaysToKeep; i++ {
						subdirectory := today.Add(time.Duration(i) * 24 * time.Hour).UTC().Format("2006-01-02")
						require.NoError(t, afs.MkdirAll(filepath.Join(test.directory, subdirectory), test.directoryPermissions))
						fullPath := fmt.Sprintf("%s/%s/", test.directory, subdirectory)

						for _, file := range files {
							filePath := fmt.Sprintf("%s/%s", subdirectory, file)
							test.files = append(test.files, filePath)
						}
						test.expectedFiles = append(test.expectedFiles, basicRollingHourLogs(fullPath))
					}
				case "Rolling Logs - New":
					// test should keep only the first RollingLogDaysToKeep days
					for i := -cmd.RollingLogDaysToKeep - 5; i < 1; i++ {
						subdirectory := today.Add(time.Duration(i) * 24 * time.Hour).UTC().Format("2006-01-02")
						require.NoError(t, afs.MkdirAll(filepath.Join(test.directory, subdirectory), test.directoryPermissions))
						fullPath := fmt.Sprintf("%s/%s/", test.directory, subdirectory)

						for _, file := range files {
							filePath := fmt.Sprintf("%s/%s", subdirectory, file)
							test.files = append(test.files, filePath)
						}

						if i >= -cmd.RollingLogDaysToKeep {
							test.expectedFiles = append(test.expectedFiles, basicRollingHourLogs(fullPath))
						}
					}

				}
				test.expectedFiles = createExpectedResults(test.expectedFiles)
			}

			// create the files
			for i, file := range test.files {

				// if the test is for duplicate logs, wait a little bit to simulate a newer last modified time
				if strings.HasPrefix(test.name, "Duplicate Logs - Same Name, One Newer") {
					if i > 0 {
						time.Sleep(300 * time.Millisecond)
					}
				}

				err := afero.WriteFile(afs, filepath.Join(test.directory, file), []byte("testytesttestboop"), test.filePermissions)
				require.NoError(t, err, "creating mock file should not produce an error")
			}

			// walk the directory
			var logMap []cmd.HourlyZeekLogs
			var walkErrors []cmd.WalkError
			var err error

			// since some of the tests are for files passed in to the import command instead of the root directory, we need to
			// simulate that accordingly
			if test.directory != "" {
				logMap, walkErrors, err = cmd.WalkFiles(afs, test.directory, test.rolling) // TODO: add rolling tests
			} else {
				logMap, walkErrors, err = cmd.WalkFiles(afs, strings.Join(test.files, " "), test.rolling)
			}

			// check if the error is expected
			if test.expectedError == nil {
				require.NoError(t, err, "running WalkFiles should not produce an error")
			} else {
				require.Error(t, err, "running WalkFiles should produce an error")
				require.ErrorIs(t, err, test.expectedError, "error should match expected value")

			}

			// verify that the returned log map matches the expected values
			require.Equal(t, test.expectedFiles, logMap, "log map should match expected value")

			// check if elements match for walk errors instead of equal so that we don't have to worry about
			// the errors being in the right order

			// verify that the returned walk errors match the expected values
			require.ElementsMatch(t, test.expectedWalkErrors, walkErrors, "walk errors should match expected value")

			// clean up the directory
			err = afs.RemoveAll(test.directory)
			require.NoError(t, err, "removing mock directory should not produce an error")
		})

	}
}

func basicRollingHourLogs(fullPath string) cmd.HourlyZeekLogs {
	return cmd.HourlyZeekLogs{
		0: {
			constants.ConnPrefix:     []string{fullPath + "conn.log"},
			constants.DNSPrefix:      []string{fullPath + "dns.log"},
			constants.SSLPrefix:      []string{fullPath + "ssl.log"},
			constants.OpenConnPrefix: []string{fullPath + "open_conn.log"},
			constants.HTTPPrefix:     []string{fullPath + "http.log"},
			constants.OpenHTTPPrefix: []string{fullPath + "open_http.log"},
			constants.OpenSSLPrefix:  []string{fullPath + "open_ssl.log"},
		},
	}
}

func TestParseHourFromFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantHour int
		wantErr  error
	}{
		{
			name:     "Simple Log with No Hour Segment",
			filename: "conn.log",
			wantHour: 0,
			wantErr:  nil,
		},

		{
			name:     "Valid hour middle range",
			filename: "log.15:30",
			wantHour: 15,
			wantErr:  nil,
		},
		{
			name:     "Valid hour lower bound",
			filename: "log.00:00",
			wantHour: 0,
			wantErr:  nil,
		},
		{
			name:     "Valid hour upper bound",
			filename: "log.23:59",
			wantHour: 23,
			wantErr:  nil,
		},
		{
			name:     "Valid Corelight Format",
			filename: "conn_20240722_12:00:00-13:00:00+0000",
			wantHour: 12,
			wantErr:  nil,
		},
		{
			name:     "Invalid Corelight Format - Bad Date",
			filename: "conn_123456789_12:00:00-13:00:00",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourFormat,
		},
		{
			name:     "Invalid Corelight Format - Ending Period",
			filename: "conn_20240722.12:00:00-13:00:00",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourFormat,
		},
		{
			name:     "Invalid Hour Range",
			filename: "log.24:00",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourRange,
		},
		{
			name:     "Non-numeric Hour Segment",
			filename: "log.ab:cd",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourFormat,
		},
		{
			name:     "Incomplete Hour Segment",
			filename: "log.:34",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourFormat,
		},
		{
			name:     "Extra characters",
			filename: "log.12x:34",
			wantHour: 0,
			wantErr:  cmd.ErrInvalidLogHourFormat,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotHour, err := cmd.ParseHourFromFilename(test.filename)
			require.Equal(t, test.wantErr, err, "expected error to be %v, got %v", test.wantErr, err)
			require.Equal(t, test.wantHour, gotHour, "expected hour to be %v, got %v", test.wantHour, gotHour)
		})
	}
}

func TestValidateDatabaseName(t *testing.T) {
	type testCase struct {
		name      string
		db        string
		shouldErr bool
	}

	tests := []testCase{
		{name: "Common name, dnscat2_ja3_strobe", db: "dnscat2_ja3_strobe"},
		{name: "Common name, combined__0000_rolling", db: "combined__0000_rolling"},
		{name: "Common name, seconion_2024_05_15", db: "combined__0000_rolling"},
		{name: "All alpha characters", db: "vsagent"},
		{name: "All alphanumeric characters", db: "dnscat20"},
		{name: "All numeric characters", db: "2024", shouldErr: true},
		{name: "Starting with a number", db: "2vsagent", shouldErr: true},
		{name: "Starting with a capital letter", db: "Vsagent", shouldErr: true},
		{name: "All caps", db: "INFORMATION_SCHEMA", shouldErr: true},
		{name: "Contains special characters", db: "ch!ck3n$tr!p", shouldErr: true},
		{name: "Contains a hyphen", db: "combined__0000-rolling", shouldErr: true},
		{name: "Starting with an underscore", db: "_vsagent", shouldErr: true},
		{name: "Ending with underscore", db: "dnscat2_", shouldErr: true},
		{name: "Length >63 characters", db: "i_am_a_very_long_database_name_that_is_over_63_characters_long_and_should_fail", shouldErr: true},
		{name: "Name is reserved: default", db: "default", shouldErr: true},
		{name: "Name is reserved: system", db: "system", shouldErr: true},
		{name: "Name is reserved: information_schema", db: "information_schema", shouldErr: true},
		{name: "Name is reserved: metadatabase", db: "metadatabase", shouldErr: true},
		{name: "Empty string", db: "", shouldErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := cmd.ValidateDatabaseName(test.db)
			require.Equal(t, test.shouldErr, err != nil, "expected error:%t, got error: %t", test.shouldErr, err)
		})
	}
}

func TestValidateLogDirectory(t *testing.T) {
	tests := []struct {
		name          string
		logDir        string
		setup         func(afs afero.Fs)
		expectedError error
	}{
		{
			name:   "Valid Directory",
			logDir: "/validlogdir",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/validlogdir", 0755))
				require.NoError(t, afero.WriteFile(afs, "/validlogdir/file.txt", []byte("content"), 0644))
			},
			expectedError: nil,
		},
		{
			name:   "Empty Directory",
			logDir: "/emptylogdir",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/emptylogdir", 0755))
			},
			expectedError: util.ErrDirIsEmpty,
		},
		{
			name:   "Path is a File",
			logDir: "/logfile.txt",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/logfile.txt", []byte("content"), 0644))
			},
			expectedError: util.ErrPathIsNotDir,
		},
		{
			name:          "Empty Log Directory",
			logDir:        "",
			setup:         func(_ afero.Fs) {},
			expectedError: cmd.ErrMissingLogDirectory,
		},
		{
			name:          "Invalid Relative Path",
			logDir:        "~/invalid/dir",
			setup:         func(_ afero.Fs) {},
			expectedError: util.ErrDirDoesNotExist,
		},
		{
			name:          "Non-Existent Directory",
			logDir:        "/nonexistentdir",
			setup:         func(_ afero.Fs) {},
			expectedError: util.ErrDirDoesNotExist,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			afs := afero.NewMemMapFs()
			test.setup(afs)

			err := cmd.ValidateLogDirectory(afs, test.logDir)

			if test.expectedError != nil {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, test.expectedError.Error(), "error message should contain expected value")
			} else {
				require.NoError(t, err, "validating log directory should not produce an error")
			}
		})
	}
}

func TestParseFolderDate(t *testing.T) {
	tests := []struct {
		name          string
		folder        string
		expectedTime  time.Time
		expectedError error
	}{
		{
			name:         "Valid Date Folder",
			folder:       "2023-06-01",
			expectedTime: time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:         "Invalid Date Folder",
			folder:       "invalid-folder",
			expectedTime: time.Date(2006, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name:          "Empty Folder Name",
			folder:        "",
			expectedTime:  time.Unix(0, 0),
			expectedError: fmt.Errorf("folder name cannot be empty"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := cmd.ParseFolderDate(test.folder)

			if test.expectedError != nil {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, test.expectedError.Error(), "error message should contain expected value")

			} else {
				require.NoError(t, err, "parsing folder date should not produce an error")
			}

			require.Equal(t, test.expectedTime, result, "the result should match the expected value")
		})
	}
}
