package integration_test

import (
	"context"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	i "github.com/activecm/rita/v5/importer"

	"reflect"

	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestValidTSV(t *testing.T) {
	validTSVSuite := new(ValidDatasetTestSuite)

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	// validTSVSuite.SetupClickHouse(t)
	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), cfg)
	require.NoError(t, err, "connecting to server should not produce an error")
	validTSVSuite.server = server

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/valid_tsv", "dnscat2_ja3_strobe", false, false)
	require.NoError(t, err)
	validTSVSuite.importResults = results

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "dnscat2_ja3_strobe", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	_, maxTimestamp, _, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	validTSVSuite.maxTimestamp = maxTimestamp
	validTSVSuite.db = db
	validTSVSuite.cfg = cfg
	suite.Run(t, validTSVSuite)
}

func TestValidJSON(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	validJSONSuite := new(ValidDatasetTestSuite)
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/valid_json", "dnscat2_ja3_strobe_json", false, false)
	require.NoError(t, err)
	validJSONSuite.importResults = results

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "dnscat2_ja3_strobe_json", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	// maxTimestamp, _, useCurrentTime, err := db.GetFirstSeenTimestamp()
	_, maxTimestamp, _, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	validJSONSuite.maxTimestamp = maxTimestamp
	validJSONSuite.db = db
	validJSONSuite.cfg = cfg
	suite.Run(t, validJSONSuite)
}

// testCounts verifies that the correct number of records of each type were written to the database
func (it *ValidDatasetTestSuite) TestCounts() {
	// t.Helper()
	t := it.T()
	var result struct {
		Count uint64 `ch:"count"`
	}

	type testCase struct {
		table               string
		expectedDBCount     int
		expectedImportCount int
		importResultCount   uint64
		uniqField           string
		msg                 string
	}

	// Verify raw log counts
	rawLogTestCases := []testCase{
		{
			table:               "conn",
			expectedDBCount:     387004 + 1023, // 1023 is the number of conn records with no host header
			expectedImportCount: 387004 + 1023,
			importResultCount:   it.importResults.Conn,
			msg:                 "written conn record count matches imported record count",
		},
		{
			table:               "openconn",
			expectedDBCount:     387004 + 1023,
			expectedImportCount: 387004 + 1023,
			importResultCount:   it.importResults.Conn,
			msg:                 "written openconn record count should be zero because they were closed",
		},
		{
			table:               "http",
			expectedDBCount:     26150 - 1023,
			expectedImportCount: 26181,
			importResultCount:   it.importResults.HTTP,
			msg:                 "written http record count matches imported record count",
		},
		{
			table:               "openhttp",
			expectedDBCount:     26150 - 1023,
			expectedImportCount: 26181,
			importResultCount:   it.importResults.OpenHTTP,
			msg:                 "written openhttp record count should be zero because they were closed",
		},
		{
			table:               "ssl",
			expectedDBCount:     86616,
			expectedImportCount: 86616,
			importResultCount:   it.importResults.SSL,
			msg:                 "written ssl record count matches imported record count",
		},
		{
			table:               "openssl",
			expectedDBCount:     86616,
			expectedImportCount: 86616,
			importResultCount:   it.importResults.OpenSSL,
			msg:                 "written openssl record count should be zero because they were closed",
		},
		{
			table:               "dns",
			expectedDBCount:     315622,
			expectedImportCount: 315622,
			importResultCount:   it.importResults.DNS,
			msg:                 "written dns record count matches imported record count",
		},
		{
			table: "pdns_raw",
			/* get number of IPv4 addresses in answers field in dns log
			cat dns.log | cut -f 10,22 | grep -v "^\-" | cut -f 2 | awk -F',' '{ for(i=1;i<=NF;i++) print $i }' \
			| grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | wc -l
			*/
			expectedDBCount:     208296,
			expectedImportCount: 208296,
			importResultCount:   it.importResults.PDNSRaw,
			msg:                 "written pdns_raw record count matches imported record count",
		},
	}
	// Verify materialized views have the right number of records in them
	materializedViewTestCases := []testCase{
		{
			table:               "uconn",
			expectedDBCount:     14756,
			expectedImportCount: 14756,
			importResultCount:   14756,
			uniqField:           "hash",
			msg:                 "uconn table has correct number of distinct hashes",
		},
		{
			table:               "usni",
			expectedDBCount:     6817,
			expectedImportCount: 6817,
			importResultCount:   6817,
			uniqField:           "hash",
			msg:                 "usni table has correct number of distinct hashes",
		},
		{
			table:               "udns",
			expectedDBCount:     78452,
			expectedImportCount: 78452,
			importResultCount:   78452,
			uniqField:           "hash",
			msg:                 "udns table has correct number of distinct hashes",
		},
		{
			table:               "pdns",
			expectedDBCount:     5671,
			expectedImportCount: 5671,
			importResultCount:   5671,
			uniqField:           "hash",
			msg:                 "pdns table has correct number of distinct hashes",
		},
		{
			table:               "exploded_dns",
			expectedDBCount:     67740,
			expectedImportCount: 67740,
			importResultCount:   67740,
			uniqField:           "fqdn",
			msg:                 "exploded_dns table has correct number of unique fqdns",
		},
	}

	for _, test := range rawLogTestCases {
		// Verify correct total import counts
		require.EqualValues(t, test.expectedImportCount, test.importResultCount, "imported correct number of %s records, got:%d", test.table, test.importResultCount)

		// Verify all parsed log records were written to database
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": test.table,
		})
		err := it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM {table:Identifier}
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, test.expectedDBCount, result.Count, test.msg)
	}

	for _, test := range materializedViewTestCases {
		// Verify correct total import counts
		require.EqualValues(t, test.expectedImportCount, test.importResultCount, "unique %s map has correct length, expected: %d, got: %d", test.table, test.expectedImportCount, test.importResultCount)

		// Verify all parsed log records were written to database
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table":  test.table,
			"column": test.uniqField,
		})
		err := it.db.Conn.QueryRow(ctx, `
				SELECT count(DISTINCT {column:Identifier}) as count FROM {table:Identifier}
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, test.expectedDBCount, result.Count, "%s, got: %d", test.msg, result.Count)
	}

}

// TestHTTPandSSLLinking makes sure that there are no more than 20 records per zeek UID in the http and open http tables
// and that the http, open http, ssl and openssl tables have duration and bytes data set in one record per zeek uid
func (it *ValidDatasetTestSuite) TestHTTPandSSLLinking() {
	t := it.T()
	var result struct {
		Count uint64 `ch:"count"`
	}

	// verify http linking wrote no more than 20 records with the same zeek uid
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
			SELECT count() as count FROM (
				SELECT zeek_uid, count() as num_with_same_zeek_uid FROM http
				GROUP BY zeek_uid
			) WHERE num_with_same_zeek_uid > 20
		`).ScanStruct(&result)
	require.NoError(t, err)
	require.EqualValues(t, 0, result.Count, "http should have no more than 20 records with the same zeek uid")

	// verify openhttp linking wrote no more than 20 records with the same zeek uid
	err = it.db.Conn.QueryRow(it.db.GetContext(), `
			SELECT count() as count FROM (
				SELECT zeek_uid, count() as num_with_same_zeek_uid FROM openhttp
				GROUP BY zeek_uid
			) WHERE num_with_same_zeek_uid > 20
		`).ScanStruct(&result)
	require.NoError(t, err)
	require.EqualValues(t, 0, result.Count, "openhttp should have no more than 20 records with the same zeek uid")

	// create list of tables which must duration and bytes fields set once per zeek uid
	durAndBytesTables := []string{"http", "openhttp", "ssl", "openssl"}

	// verify that each table in list has duration and bytes fields set once per zeek uid
	for _, table := range durAndBytesTables {
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": table,
		})
		err = it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM (
					SELECT zeek_uid, count() as num_with_dur FROM {table:Identifier}
					WHERE duration > 0 AND (src_ip_bytes > 0 OR src_bytes > 0) AND (dst_ip_bytes > 0 OR dst_bytes > 0)
					GROUP BY zeek_uid
				) WHERE num_with_dur != 1
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, (table + " must have duration and bytes fields set once per zeek uid"))
	}

}

// TestTableFieldsThatCannotBeUnset makes sure that fields which cannot be unset -
// (zeek_uid, hash, src, dst, src_nuid, dst_nuid, query and fqdn) are not unset
func (it *ValidDatasetTestSuite) TestTableFieldsThatCannotBeUnset() {

	var result struct {
		Count uint64 `ch:"count"`
	}

	// ✅ HASH
	it.T().Run("ValidateHash", func(t *testing.T) {
		// list of tables which must have set hash fields
		hashTables := []string{"conn", "uconn", "openconn", "http", "usni", "openhttp", "ssl", "openssl", "dns", "udns", "pdns_raw", "pdns", "tls_proto", "http_proto", "threat_mixtape"}

		// verify that each table in list has no unset zeek uids
		for _, table := range hashTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
					SELECT count() AS count FROM {table:Identifier}
					WHERE hash==toFixedString('',16) OR hex(hash)=='00000000000000000000000000000000'
				`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset hash fields"))
		}
	})

	// ✅ IMPORT_ID
	it.T().Run("ValidateImportID", func(t *testing.T) {
		// list of tables which must have set import_id fields
		importIDTables := []string{"conn", "threat_mixtape"}

		// verify that each table in list has no unset import_id fields
		for _, table := range importIDTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
					SELECT count() AS count FROM {table:Identifier}
					WHERE import_id==toFixedString('',16) OR hex(import_id)=='00000000000000000000000000000000' OR import_id=='' OR import_id IS NULL
				`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset import_id fields"))
		}
	})

	// ✅ ZEEK_UID
	it.T().Run("ValidateZeekUID", func(t *testing.T) {
		// list of tables which must have set zeek uid fields
		zeekUIDTables := []string{"conn", "openconn", "dns", "http", "openhttp", "ssl", "openssl"}

		// verify that each table in list has no unset zeek uids
		for _, table := range zeekUIDTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
					SELECT count() AS count FROM {table:Identifier}
					WHERE zeek_uid==toFixedString('',16) OR hex(zeek_uid)=='00000000000000000000000000000000'
				`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset zeek uid fields"))
		}
	})

	// ✅ TIMESTAMP
	it.T().Run("ValidateTimestamp", func(t *testing.T) {
		// list of tables which must have set ts field
		tsTables := []string{"conn", "openconn", "http", "openhttp", "ssl", "openssl", "dns", "pdns_raw"}

		// verify that each table in list has no unset ts fields
		for _, table := range tsTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
				SELECT count() AS count FROM {table:Identifier}
				WHERE ts=='1970-01-01 00:00:00' OR ts=='2036-02-07 06:28:16' OR ts >='2106-02-07 06:28:15'
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset or invalid timestamp fields"))
		}
	})

	// ✅ IMPORT TIME
	it.T().Run("ValidateImportTime", func(t *testing.T) {
		// list of tables which must have set ts field
		tsTables := []string{"conn", "http", "ssl", "dns", "pdns_raw"}

		// verify that each table in list has no unset ts fields
		for _, table := range tsTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
					SELECT count() AS count FROM {table:Identifier}
					WHERE import_time=='1970-01-01 00:00:00' OR import_time=='2036-02-07 06:28:16' OR import_time >='2106-02-07 06:28:15'
				`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset or invalid timestamp fields"))
		}
	})

	// ✅ HOUR
	it.T().Run("ValidateHour", func(t *testing.T) {
		// list of tables which must have set hour fields
		hourTables := []string{"uconn", "usni", "udns", "exploded_dns", "threat_mixtape", "mime_type_uris", "port_info", "tls_proto", "http_proto", "rare_signatures"}

		// verify that each table in list has no unset hour fields
		for _, table := range hourTables {
			columnName := "hour"
			if table == "threat_mixtape" {
				columnName = "analyzed_at"
			}
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table":  table,
				"column": columnName,
			})
			err := it.db.Conn.QueryRow(ctx, `
				SELECT count() AS count FROM {table:Identifier}
				WHERE {column:Identifier}=='1970-01-01 00:00:00' OR {column:Identifier}=='2036-02-07 06:28:16' OR {column:Identifier} >='2106-02-07 06:28:15'
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset or invalid hour fields"))
		}
	})

	// ✅ IMPORT HOUR
	it.T().Run("ValidateImportHour", func(t *testing.T) {
		// list of tables which must have set hour fields
		hourTables := []string{"uconn", "usni", "udns", "exploded_dns", "mime_type_uris", "port_info", "tls_proto", "http_proto", "rare_signatures"}

		// verify that each table in list has no unset hour fields
		for _, table := range hourTables {

			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})
			err := it.db.Conn.QueryRow(ctx, `
					SELECT count() AS count FROM {table:Identifier}
					WHERE import_hour=='1970-01-01 00:00:00' OR import_hour=='2036-02-07 06:28:16' OR import_hour >='2106-02-07 06:28:15'
				`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset or invalid hour fields"))
		}
	})

	// ✅ SRC / SRC_NUID
	it.T().Run("ValidateSrc", func(t *testing.T) {
		// list of tables which must have set src/src_nuid fields
		srcTables := []string{"conn", "uconn", "openconn", "http", "usni", "openhttp", "ssl", "openssl", "dns", "udns", "pdns_raw", "pdns"}

		// verify that each table in list has no unset src and src_nuid fields
		for _, table := range srcTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})

			// check src
			err := it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM {table:Identifier}
				WHERE src == '::'
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset src fields"))

			// check src_nuid
			err = it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM {table:Identifier}
				WHERE src_nuid == '00000000-0000-0000-0000-000000000000'
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset src_nuid fields"))
		}
	})

	// ✅ DST / DST_NUID
	it.T().Run("ValidateDst", func(t *testing.T) {
		// list of tables which must have set dst/dst_nuid fields
		dstTables := []string{"conn", "uconn", "openconn", "http", "usni", "openhttp", "ssl", "openssl", "dns", "udns", "pdns_raw", "pdns"}

		// verify that each table in list has no unset dst and dst_nuid fields
		for _, table := range dstTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})

			// check dst
			err := it.db.Conn.QueryRow(ctx, `
						SELECT count() as count FROM {table:Identifier}
						WHERE dst == '::'
					`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset dst fields"))

			// check dst_nuid
			err = it.db.Conn.QueryRow(ctx, `
						SELECT count() as count FROM {table:Identifier}
						WHERE dst_nuid == '00000000-0000-0000-0000-000000000000'
					`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset dst_nuid fields"))
		}

	})

	// ✅  ICMP type / ICMP code
	it.T().Run("ValidateICMPTypeCode", func(t *testing.T) {
		// list of tables which must have set icmp_type & icmp_code fields
		connTables := []string{"conn", "openconn"}

		// verify that each table in list has no unset dst and dst_nuid fields
		for _, table := range connTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})

			// check non-icmp entries
			err := it.db.Conn.QueryRow(ctx, `
						SELECT count() as count FROM {table:Identifier}
						WHERE proto != 'icmp' AND (icmp_type > -1 OR icmp_code > -1)
					`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have icmp type or code greater than -1 when proto is not icmp"))
		}

	})

	// ✅ QUERY
	it.T().Run("ValidateQuery", func(t *testing.T) {
		// list of tables which must have set query field
		queryTables := []string{"dns", "pdns_raw"}

		// verify that each table in list has no unset query fields
		for _, table := range queryTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})

			err := it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM {table:Identifier} WHERE query == ''
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, (table + " must not have unset query fields"))
		}
	})

	// ✅ FQDN
	it.T().Run("ValidateQuery", func(t *testing.T) {
		// list of tables which must have set fqdn filed
		fqdnTables := []string{"udns", "pdns", "exploded_dns"}

		// verify that each table in list has no unset fqdn fields
		for _, table := range fqdnTables {
			ctx := it.db.QueryParameters(clickhouse.Parameters{
				"table": table,
			})

			err := it.db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM {table:Identifier} WHERE fqdn == ''
			`).ScanStruct(&result)
			require.NoError(t, err)
			require.EqualValues(t, 0, result.Count, "%s must not have unset fqdn fields, got: %d", table, result.Count)
		}
	})

}

// TestMixtapeFields
// go test -v ./integration -run TestValidTSV/TestMixtapeFields
func (it *ValidDatasetTestSuite) TestMixtapeFields() {

	table := "threat_mixtape"
	ctx := it.db.QueryParameters(clickhouse.Parameters{
		"table": table,
	})

	var result struct {
		Count uint64 `ch:"count"`
	}

	// ✅ last_seen : ensure that every last seen date in the mixtape is valid (greater than 0 and less than epoch overflow)
	it.T().Run("ValidateLastSeen", func(t *testing.T) {
		// get count of mixtape records with invalid last_seen fields
		err := it.db.Conn.QueryRow(ctx, `
			SELECT count() as count FROM {table:Identifier}
			WHERE last_seen=='1970-01-01 00:00:00' OR last_seen=='2036-02-07 06:28:16' OR last_seen >='2106-02-07 06:28:15'
		`).ScanStruct(&result)

		// ensure that there is no error
		require.NoError(t, err)

		// ensure that there are no records with invalid last_seen fields
		require.EqualValues(t, 0, result.Count, "last_seen must not have unset or invalid timestamp fields")
	})

	// // verify that each table in list has no unset ts fields
	// for _, table := range tsTables {
	// 	ctx := it.db.QueryParameters(clickhouse.Parameters{
	// 		"table": table,
	// 	})
	// 	err := it.db.Conn.QueryRow(ctx, `
	// 		SELECT count() AS count FROM {table:Identifier}
	// 		WHERE ts=='1970-01-01 00:00:00' OR ts=='2036-02-07 06:28:16' OR ts >='2106-02-07 06:28:15'
	// 	`).ScanStruct(&result)
	// 	require.NoError(t, err)
	// 	require.EqualValues(t, 0, result.Count, (table + " must not have unset or invalid timestamp fields"))
	// }
}

// TestTSVLogFieldParsing verifies that every required field in each tsv log type has parsed data in the database
func TestTSVLogFieldParsing(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	// get config
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	// update config with clickhouse connection
	cfg.DBConnection = dockerInfo.clickhouseConnection
	cfg.Filter.FilterExternalToInternal = false
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/open_conns/open", "test_tsv_field_parsing", false, false)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "test_tsv_field_parsing", cfg, nil)
	require.NoError(t, err)

	// test tsv log field parsing
	testLogFieldParsing(t, db, reflect.TypeOf(i.ConnEntry{}), "conn")
	testLogFieldParsing(t, db, reflect.TypeOf(i.ConnEntry{}), "openconn")
	testLogFieldParsing(t, db, reflect.TypeOf(i.HTTPEntry{}), "http")
	testLogFieldParsing(t, db, reflect.TypeOf(i.HTTPEntry{}), "openhttp")
	testLogFieldParsing(t, db, reflect.TypeOf(i.SSLEntry{}), "ssl")
	testLogFieldParsing(t, db, reflect.TypeOf(i.SSLEntry{}), "openssl")
	testLogFieldParsing(t, db, reflect.TypeOf(i.DNSEntry{}), "dns")
	testLogFieldParsing(t, db, reflect.TypeOf(i.DNSEntry{}), "pdns_raw")
}

// TestJSONLogFieldParsing verifies that every required field in each json log type has parsed data in the database
func TestJSONLogFieldParsing(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	// load config
	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	// update config with clickhouse connection
	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/json_with_all_fields", "json_with_all_fields", false, false)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "json_with_all_fields", cfg, nil)
	require.NoError(t, err)

	// test json log field parsing
	testLogFieldParsing(t, db, reflect.TypeOf(i.ConnEntry{}), "conn")
	testLogFieldParsing(t, db, reflect.TypeOf(i.ConnEntry{}), "openconn")
	testLogFieldParsing(t, db, reflect.TypeOf(i.HTTPEntry{}), "http")
	testLogFieldParsing(t, db, reflect.TypeOf(i.HTTPEntry{}), "openhttp")
	testLogFieldParsing(t, db, reflect.TypeOf(i.SSLEntry{}), "ssl")
	testLogFieldParsing(t, db, reflect.TypeOf(i.SSLEntry{}), "openssl")
	testLogFieldParsing(t, db, reflect.TypeOf(i.DNSEntry{}), "dns")
	testLogFieldParsing(t, db, reflect.TypeOf(i.DNSEntry{}), "pdns_raw")

}

// testLogFieldParsing determines which fields a log entry needs to have and verifies that they are parsed in the database
func testLogFieldParsing(t *testing.T, db *database.DB, log reflect.Type, table string) {
	t.Helper()

	// get list of string fields in log entry
	var stringFields []string
	for i := 0; i < log.NumField(); i++ {
		if log.Field(i).Type.Kind() == reflect.String {
			stringFields = append(stringFields, log.Field(i).Tag.Get("ch"))
		}
	}

	// verify string type fields
	checkLogTypeStringFields(t, db, table, stringFields)

	// get list of number fields in log entry
	var numFields []string
	for i := 0; i < log.NumField(); i++ {
		if typeIsNumber(log.Field(i).Type.Kind()) {
			numFields = append(numFields, log.Field(i).Tag.Get("ch"))
		}
	}

	// verify number type fields
	checkLogTypeNumFields(t, db, table, numFields)

	// TODO: verify array fields

}

// checkLogTypeStringFields verifies that every string field in a log type has parsed data in the database
func checkLogTypeStringFields(t *testing.T, db *database.DB, table string, stringFields []string) {
	t.Helper()

	var result struct {
		Count uint64 `ch:"count"`
	}

	// verify string type fields
	for _, field := range stringFields {
		// skip this field since it is populated after parsing
		if field == "missing_host_useragent" {
			continue
		}
		ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
			"table":  table,
			"column": field,
		}))

		err := db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM (
					SELECT count() as num_set FROM {table:Identifier} where {column:Identifier} != ''
				) WHERE num_set == 0
		  `).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "%v must contain some records with a parsed %v field", table, field)

		err = db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM (
					SELECT count() as num_set FROM {table:Identifier} where {column:Identifier} != ''
				) WHERE num_set == 0
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "%v must contain some records with a parsed %v field", table, field)
	}
}

// checkLogTypeNumFields verifies that every number field in a log type has parsed data in the database
func checkLogTypeNumFields(t *testing.T, db *database.DB, table string, numFields []string) {
	t.Helper()

	var result struct {
		Count uint64 `ch:"count"`
	}

	// verify string type fields
	for _, field := range numFields {
		// skip these fields since they are populated after parsing
		if field == "filtered" || field == "missing_host_header" || field == "dst_local" ||
			field == "icmp_type" || field == "icmp_code" {
			continue
		}

		// skip these fields since they're not filled out in the test data
		if field == "resumed" || field == "recursion_desired" || field == "recursion_available" {
			continue
		}

		if field == "rejected" && table == "pdns_raw" {
			continue
		}

		ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
			"table":  table,
			"column": field,
		}))

		err := db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM (
					SELECT count() as num_set FROM {table:Identifier} where {column:Identifier} > 0
				) WHERE num_set == 0
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "%v must contain some records with a parsed %v field", table, field)

		err = db.Conn.QueryRow(ctx, `
				SELECT count() as count FROM (
					SELECT count() as num_set FROM {table:Identifier} where {column:Identifier} > 0
				) WHERE num_set == 0
			`).ScanStruct(&result)
		require.NoError(t, err)
		require.EqualValues(t, 0, result.Count, "%v must contain some records with a parsed %v field", table, field)
	}
}

// typeIsNumber determines if a type is a number
func typeIsNumber(varType reflect.Kind) bool {
	switch varType {
	case reflect.Bool:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Int:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		fallthrough
	case reflect.Float32:
		fallthrough
	case reflect.Float64:
		return true
	default:
		return false
	}

}

// add tests for filtering
