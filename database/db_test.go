package database_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/activecm/rita/cmd"
	"github.com/activecm/rita/database"
	"github.com/activecm/rita/util"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func (d *DatabaseTestSuite) TestConnectToDB() {

	// create and connect to a new database
	d.Run("Connect to Existing Database", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to createddatabase should not produce an error")
		require.NotNil(t, db)
	})

	// attempt to connect to a non-existent database
	d.Run("Connect to Non-Existent Database", func() {
		t := d.T()
		db, err := database.ConnectToDB(context.Background(), "nonExistentDB", d.cfg, nil)
		require.Error(t, err, "connecting to a non-existent database should produce an error")
		require.Nil(t, db)
	})

	// attempt to connect with invalid configuration
	d.Run("Invalid Configuration", func() {
		t := d.T()
		invalidCfg := *d.cfg
		invalidCfg.DBConnection = "invalid connection string"

		db, err := database.ConnectToDB(context.Background(), "testDB", &invalidCfg, nil)
		require.Error(t, err, "connecting with invalid configuration should produce an error")
		require.Nil(t, db)
	})

	// attempt to connect with a cancelled context
	d.Run("Cancel Context", func() {
		t := d.T()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// attempt to connect with a cancelled context
		db, err := database.ConnectToDB(ctx, "testDB", d.cfg, nil)
		require.Error(t, err, "connecting with a cancelled context should produce an error")
		require.Nil(t, db)
	})
}

func (d *DatabaseTestSuite) TestMinMaxTimestamps() {
	d.Run("24 Hour Dataset", func() {
		t := d.T()
		// import a dataset with 24 hours of data
		results, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		// get the min and max timestamps from a test function that queries the conn, openconn, and dns tables
		_, max := getMinMaxTimestampsFromTables(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching beacon min and max timestamps should not produce an error")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min and max timestamps should not produce an error")

		// validate that the current time is not used
		require.False(t, useCurrentTime, "useCurrentTime should be false")

		// check that the timestamps are within the expected range
		require.True(t, maxTS.After(minTS), "max timestamp should be after min timestamp")

		// capped min timestamp
		minTSCapped := max.Add(-24 * time.Hour)
		require.InDelta(t, 24.0, maxTS.Sub(minTS).Hours(), 0.1, "timestamp difference should be close to 24 hours")

		fmt.Println("Max Timestamp: ", maxTS)
		fmt.Println("Min Timestamp: ", minTS)

		// check that the true timestamps match the min and max timestamps from the test function
		require.Equal(t, minTSCapped, minTS, "min timestamp should match min timestamp from the test function")
		require.Equal(t, max, maxTS, "max timestamp should match max timestamp from the test function")

		// check that the beacon timestamps are within the expected range
		require.True(t, maxTSBeacon.Before(max) || maxTSBeacon.Equal(max), "max beacon timestamp should be before or equal to max timestamp from the test function")
		require.True(t, minTSBeacon.After(minTSCapped) || minTSBeacon.Equal(minTSCapped), "min beacon timestamp should be after or equal to min timestamp from the test function")
	})

	d.Run("Less Than 24 Hours of Data", func() {
		t := d.T()
		// import a dataset with < 24 hours of data
		results, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/proxy_rolling", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		// get the min and max timestamps from a test function that queries the conn, openconn, and dns tables
		min, max := getMinMaxTimestampsFromTables(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching beacon min and max timestamps should not produce an error")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min and max timestamps should not produce an error")

		// validate that the current time is not used
		require.False(t, useCurrentTime, "useCurrentTime should be false")

		// check that the timestamps are within the expected range
		require.True(t, maxTS.After(minTS), "max timestamp should be after min timestamp")
		require.Less(t, maxTS.Sub(minTS).Hours(), 24.0, "timestamp difference should be less than 24 hours")

		// check that the max timestamp matches the max timestamps from the test function
		require.Equal(t, max, maxTS, "max timestamp should match max timestamp from test function")

		// since the dataset is less than 24 hours, the min timestamp should match the min timestamp from the test function
		require.Equal(t, min, minTS, "min timestamp should match min timestamp from test function")

		// check that the beacon timestamps are within the expected range
		require.True(t, maxTSBeacon.Before(max) || maxTSBeacon.Equal(max), "max beacon timestamp should be before or equal to max timestamp from the test function")
		require.True(t, minTSBeacon.After(min) || minTSBeacon.Equal(min), "min beacon timestamp should be after or equal to min timestamp from the test function")
	})

	d.Run("Greater Than 24 Hours of Data", func() {
		t := d.T()

		afs := afero.NewMemMapFs()

		// create directory
		directory := "/logs"
		err := afs.Mkdir(directory, os.FileMode(0o775))
		require.NoError(t, err, "creating directory should not produce an error")

		// create mock data file
		fileName := "conn.log"
		path := filepath.Join(directory, fileName)
		file, err := afs.Create(path)
		require.NoError(t, err, "creating file should not produce an error")

		// set file permissions
		err = afs.Chmod(path, os.FileMode(0o775))
		require.NoError(t, err, "changing file permissions should not produce an error")

		// generate timestamp from current time and format to the timestamp format used in the log file
		currentTime := time.Now().UTC()
		formattedMaxTime := fmt.Sprintf("%d.%06d", currentTime.Unix(), currentTime.Nanosecond()/1000)

		// create interval timestamps of 4 hours ago
		fourHoursAgo := currentTime.Add(-4 * time.Hour)
		formattedTime := fmt.Sprintf("%d.%06d", fourHoursAgo.Unix(), fourHoursAgo.Nanosecond()/1000)

		// create timestamp for 48 hours ago
		twoDaysAgo := currentTime.Add(-48 * time.Hour)
		formattedMinTime := fmt.Sprintf("%d.%06d", twoDaysAgo.Unix(), twoDaysAgo.Nanosecond()/1000)

		// create mock data
		log := []byte("#separator \\x09\n" +
			"#set_separator\t,\n" +
			"#empty_field\t(empty)\n" +
			"#unset_field\t-\n" +
			"#path\tconn\n" +
			"#open\t2019-02-28-12-07-01\n" +
			"#fields\tts\tuid\tid.orig_h\tid.resp_h\n" +
			"#types\ttime\tstring\taddr\taddr\n" +
			formattedMaxTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n" +
			formattedMinTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n",
		)
		bytesWritten, err := file.Write(log)
		require.NoError(t, err, "writing data to file should not produce an error")
		require.Equal(t, len(log), bytesWritten, "number of bytes written should be equal to the length of the log data")

		err = file.Close()
		require.NoError(t, err, "closing file should not produce an error")

		// import the mock data
		results, err := cmd.RunImportCmd(time.Now(), d.cfg, afs, directory, "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		// get the min and max timestamps from a test function that queries the conn, openconn, and dns tables
		min, max := getMinMaxTimestampsFromTables(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching beacon min and max timestamps should not produce an error")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min and max timestamps should not produce an error")

		// validate that the current time is not used
		require.False(t, useCurrentTime, "useCurrentTime should be false")

		// check that the timestamps are within the expected range
		require.True(t, maxTS.After(minTS), "max timestamp should be after min timestamp")
		require.InDelta(t, 24.0, maxTS.Sub(minTS).Hours(), 0.1, "timestamp difference should be close to 24 hours")

		// check that the max timestamp matches the max timestamps from the test function
		require.Equal(t, max, maxTS, "max timestamp should match max timestamp from test function")

		// since the dataset is > 24 hours, the min timestamp will get capped to 24 hours from the max timestamp
		require.NotEqual(t, min, minTS, "min timestamp should not match min timestamp from test function")
		require.Equal(t, maxTS.Add(-24*time.Hour), minTS, "min timestamp should be 24 hours from max timestamp")

		// check that the beacon timestamps are within the expected range
		require.True(t, maxTSBeacon.Before(max) || maxTSBeacon.Equal(max), "max beacon timestamp should be before or equal to max timestamp from the test function")
		require.True(t, minTSBeacon.After(maxTS.Add(-24*time.Hour)) || minTSBeacon.Equal(maxTS.Add(-24*time.Hour)), "min beacon timestamp should be after or equal to min timestamp from the test function")
	})

	d.Run("Rolling, Max Timestamp < 24Hrs Ago", func() {
		t := d.T()
		afs := afero.NewMemMapFs()

		// create directory
		directory := "/logs"
		err := afs.Mkdir(directory, os.FileMode(0o775))
		require.NoError(t, err, "creating directory should not produce an error")

		// create mock data file
		fileName := "conn.log"
		path := filepath.Join(directory, fileName)
		file, err := afs.Create(path)
		require.NoError(t, err, "creating file should not produce an error")

		// set file permissions
		err = afs.Chmod(path, os.FileMode(0o775))
		require.NoError(t, err, "changing file permissions should not produce an error")

		// generate timestamp from current time and format to the timestamp format used in the log file
		maxTime := time.Now().UTC().Add(-1 * time.Hour)
		formattedMaxTime := fmt.Sprintf("%d.%06d", maxTime.Unix(), maxTime.Nanosecond()/1000)

		// create interval timestamps of 4 hours ago
		fourHoursAgo := maxTime.Add(-4 * time.Hour)
		formattedTime := fmt.Sprintf("%d.%06d", fourHoursAgo.Unix(), fourHoursAgo.Nanosecond()/1000)

		// create timestamp for 24 hours ago
		minTime := maxTime.Add(-24 * time.Hour)
		formattedMinTime := fmt.Sprintf("%d.%06d", minTime.Unix(), minTime.Nanosecond()/1000)

		// create mock data
		log := []byte("#separator \\x09\n" +
			"#set_separator\t,\n" +
			"#empty_field\t(empty)\n" +
			"#unset_field\t-\n" +
			"#path\tconn\n" +
			"#open\t2019-02-28-12-07-01\n" +
			"#fields\tts\tuid\tid.orig_h\tid.resp_h\n" +
			"#types\ttime\tstring\taddr\taddr\n" +
			formattedMaxTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n" +
			formattedMinTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n",
		)
		bytesWritten, err := file.Write(log)
		require.NoError(t, err, "writing data to file should not produce an error")
		require.Equal(t, len(log), bytesWritten, "number of bytes written should be equal to the length of the log data")

		err = file.Close()
		require.NoError(t, err, "closing file should not produce an error")

		// import the mock data
		results, err := cmd.RunImportCmd(time.Now(), d.cfg, afs, directory, "testDB", true, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		// get the min and max timestamps from a test function that queries the conn, openconn, and dns tables
		min, max := getMinMaxTimestampsFromTables(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching beacon min and max timestamps should not produce an error")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min and max timestamps should not produce an error")

		// validate that the current time should be used since the max timestamp is <= 24 hours ago and the dataset is rolling
		require.True(t, useCurrentTime, "useCurrentTime should be true")

		// check that the timestamps are within the expected range
		require.True(t, maxTS.After(minTS), "max timestamp should be after min timestamp")
		require.InDelta(t, 24.0, maxTS.Sub(minTS).Hours(), 0.1, "timestamp difference should be close to 24 hours")

		// check that the timestamps match the min and max timestamps from the test function
		require.Equal(t, min, minTS, "min timestamp should match min timestamp from the test function")
		require.Equal(t, max, maxTS, "max timestamp should match max timestamp from the test function")

		// check that the beacon timestamps are within the expected range
		require.True(t, maxTSBeacon.Before(max) || maxTSBeacon.Equal(max), "max beacon timestamp should be before or equal to max timestamp from the test function")
		require.True(t, minTSBeacon.After(min) || minTSBeacon.Equal(min), "min beacon timestamp should be after or equal to min timestamp from the test function")
	})

	d.Run("Rolling, Max Timestamp > 24Hrs Ago", func() {
		t := d.T()
		afs := afero.NewMemMapFs()

		// create directory
		directory := "/logs"
		err := afs.Mkdir(directory, os.FileMode(0o775))
		require.NoError(t, err, "creating directory should not produce an error")

		// create mock data file
		fileName := "conn.log"
		path := filepath.Join(directory, fileName)
		file, err := afs.Create(path)
		require.NoError(t, err, "creating file should not produce an error")

		// set file permissions
		err = afs.Chmod(path, os.FileMode(0o775))
		require.NoError(t, err, "changing file permissions should not produce an error")

		// generate timestamp from current time and format to the timestamp format used in the log file
		maxTime := time.Now().UTC().Add(-25 * time.Hour)
		formattedMaxTime := fmt.Sprintf("%d.%06d", maxTime.Unix(), maxTime.Nanosecond()/1000)

		// create interval timestamps of 4 hours ago
		fourHoursAgo := maxTime.Add(-4 * time.Hour)
		formattedTime := fmt.Sprintf("%d.%06d", fourHoursAgo.Unix(), fourHoursAgo.Nanosecond()/1000)

		// create timestamp for 48 hours ago
		minTime := maxTime.Add(-48 * time.Hour)
		formattedMinTime := fmt.Sprintf("%d.%06d", minTime.Unix(), minTime.Nanosecond()/1000)

		// create mock data
		log := []byte("#separator \\x09\n" +
			"#set_separator\t,\n" +
			"#empty_field\t(empty)\n" +
			"#unset_field\t-\n" +
			"#path\tconn\n" +
			"#open\t2019-02-28-12-07-01\n" +
			"#fields\tts\tuid\tid.orig_h\tid.resp_h\n" +
			"#types\ttime\tstring\taddr\taddr\n" +
			formattedMaxTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT121\t10.0.0.1\t52.12.0.1\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT122\t10.0.0.2\t52.12.0.2\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT123\t10.0.0.3\t52.12.0.3\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT124\t10.0.0.4\t52.12.0.4\n" +
			formattedTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n" +
			formattedMinTime + "\tCxT125\t10.0.0.5\t52.12.0.5\n",
		)
		bytesWritten, err := file.Write(log)
		require.NoError(t, err, "writing data to file should not produce an error")
		require.Equal(t, len(log), bytesWritten, "number of bytes written should be equal to the length of the log data")

		err = file.Close()
		require.NoError(t, err, "closing file should not produce an error")

		// import the mock data
		results, err := cmd.RunImportCmd(time.Now(), d.cfg, afs, directory, "testDB", true, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		// get the min and max timestamps from a test function that queries the conn, openconn, and dns tables
		min, max := getMinMaxTimestampsFromTables(t, db, results.ImportID[0])
		require.NoError(t, err, "getting min/max timestamps should not error")

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching beacon min and max timestamps should not produce an error")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min and max timestamps should not produce an error")

		// validate that the current time is not used
		require.False(t, useCurrentTime, "useCurrentTime should be false")

		// check that the timestamps are within the expected range
		require.True(t, maxTS.After(minTS), "max timestamp should be after min timestamp")
		require.InDelta(t, 24.0, maxTS.Sub(minTS).Hours(), 0.1, "timestamp difference should be close to 24 hours")

		// check that the max timestamp matches the max timestamps from the test function
		require.Equal(t, max, maxTS, "max timestamp should match max timestamp from test function")

		// since the dataset is > 24 hours, the min timestamp will get capped to 24 hours from the max timestamp
		require.NotEqual(t, min, minTS, "min timestamp should not match min timestamp from test function")
		require.Equal(t, maxTS.Add(-24*time.Hour), minTS, "min timestamp should be 24 hours from max timestamp")

		// check that the beacon timestamps are within the expected range
		require.True(t, maxTSBeacon.Before(max) || maxTSBeacon.Equal(max), "max beacon timestamp should be before or equal to max timestamp from the test function")
		require.True(t, minTSBeacon.After(maxTS.Add(-24*time.Hour)) || minTSBeacon.Equal(maxTS.Add(-24*time.Hour)), "min beacon timestamp should be after or equal to min timestamp from the test function")
	})

	d.Run("Non-Existent Database / Invalid Connection", func() {
		t := d.T()
		db := database.DB{}

		// fetch the beacon minimum and maximum timestamps
		minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
		require.Error(t, err, "fetching beacon min and max timestamps should produce an error")
		require.Equal(t, minTSBeacon, time.Unix(0, 0), "max timestamp should be zero unix time")
		require.Equal(t, maxTSBeacon, time.Unix(0, 0), "min timestamp should be zero unix time")
		require.Equal(t, err, database.ErrInvalidDatabaseConnection, "error should be invalid database connection")

		// fetch the true minimum and maximum timestamps
		minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
		require.Error(t, err, "fetching min and max timestamps should produce an error")

		require.Equal(t, maxTS, time.Unix(0, 0), "max timestamp should be zero unix time")
		require.Equal(t, minTS, time.Unix(0, 0), "min timestamp should be zero unix time")
		require.False(t, useCurrentTime, "value passed back to useCurrentTime should be false")
		require.Equal(t, err, database.ErrInvalidDatabaseConnection, "error should be invalid database connection")

	})
}

func getMinMaxTimestampsFromTables(t *testing.T, db *database.DB, importID util.FixedString) (time.Time, time.Time) { // uses valid dataset
	t.Helper()

	type minMaxRes struct {
		Min time.Time `ch:"min_timestamp"`
		Max time.Time `ch:"max_timestamp"`
	}

	var result minMaxRes

	// set context with importID and database parameters
	ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
		"importID": importID.Hex(),
		"database": db.GetSelectedDB(),
	}))

	// get min and max timestamps from the conn, openconn, and udns tables
	err := db.Conn.QueryRow(ctx, `
			SELECT MIN(ts) AS min_timestamp, MAX(ts) AS max_timestamp
			FROM (
				SELECT ts FROM {database:Identifier}.conn
				UNION ALL
				SELECT ts FROM {database:Identifier}.openconn
				UNION ALL
				SELECT hour as ts FROM {database:Identifier}.udns
			) AS combined_timestamps
		`).ScanStruct(&result)
	require.NoError(t, err)

	fmt.Println("Min Timestamp: ", result.Min)
	fmt.Println("Max Timestamp: ", result.Max)

	return result.Min, result.Max
}

func (d *DatabaseTestSuite) TestGetNetworkSize() {
	d.Run("Valid TSV Dataset", func() {
		t := d.T()
		// import a dataset
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		var result struct {
			Count uint64 `ch:"count"`
		}

		// verify http linking wrote no more than 20 records with the same zeek uid
		err = db.Conn.QueryRow(db.GetContext(), `
				SELECT count() as count FROM conn
			`).ScanStruct(&result)
		require.NoError(t, err, "querying conn table should not produce an error")

		fmt.Println("Count: ", result.Count)

		// get the min timestamp
		minTS, _, notFromConn, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching min timestamp should not produce an error")

		// validate which table min max is from
		require.False(t, notFromConn, "min and max timestamps should be from conn table")

		// get the network size (number of unique internal hosts for the past 24 hours)
		networkSize, err := db.GetNetworkSize(minTS)
		require.NoError(t, err, "getting network size should not produce an error")

		// verify the expected network size
		require.Greater(t, networkSize, uint64(0), "network size should be greater than zero")

		require.Equal(t, 15, int(networkSize), "network size for valid tsv dataset should match expected value")
	})

	d.Run("Mocked Log File with Duplicate Internal Hosts", func() {
		t := d.T()
		afs := afero.NewMemMapFs()

		// create directory
		directory := "/logs"
		err := afs.Mkdir(directory, os.FileMode(0o775))
		require.NoError(t, err, "creating directory should not produce an error")

		// create mock data file
		fileName := "conn.log"
		path := filepath.Join(directory, fileName)
		file, err := afs.Create(path)
		require.NoError(t, err, "creating file should not produce an error")

		// set file permissions
		err = afs.Chmod(path, os.FileMode(0o775))
		require.NoError(t, err, "changing file permissions should not produce an error")

		// create mock data with duplicates and write data to file
		log := []byte("#separator \\x09\n" +
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
		bytesWritten, err := file.Write(log)
		require.NoError(t, err, "writing data to file should not produce an error")
		require.Equal(t, len(log), bytesWritten, "number of bytes written should be equal to the length of the log data")

		err = file.Close()
		require.NoError(t, err, "closing file should not produce an error")

		// import the mock data
		_, err = cmd.RunImportCmd(time.Now(), d.cfg, afs, directory, "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		var result struct {
			Count uint64 `ch:"count"`
		}

		// create a query to count number of conn records
		err = db.Conn.QueryRow(db.GetContext(), `
				SELECT count() as count FROM conn
			`).ScanStruct(&result)
		require.NoError(t, err, "querying conn table should not produce an error")
		require.Equal(t, uint64(10), result.Count, "number of records in conn table should be 10")

		// get the min timestamp
		minTS, _, _, err := db.GetBeaconMinMaxTimestamps()
		require.NoError(t, err, "fetching min timestamp should not produce an error")

		// get the network size (number of unique internal hosts for the past 24 hours)
		networkSize, err := db.GetNetworkSize(minTS)
		require.NoError(t, err, "getting network size should not produce an error")

		// verify the expected network size
		fmt.Println("Network Size: ", networkSize)
		require.Greater(t, networkSize, uint64(0), "network size should be greater than zero")
		require.Equal(t, uint64(5), networkSize, "network size for test 2 should be match expected value")

		// remove the mock directory
		require.NoError(t, afs.RemoveAll(directory), "removing mock directory should not produce an error")

	})

	d.Run("Open Conn Dataset", func() {
		t := d.T()
		// import a dataset
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/open_conns/open/open_conn.log", "testDBzzzz", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		// connect to the database
		db, err := database.ConnectToDB(context.Background(), "testDBzzzz", d.cfg, nil)
		require.NoError(t, err, "connecting to database should not produce an error")

		var result struct {
			Count uint64 `ch:"count"`
		}

		// validate that number of conn records is zero
		err = db.Conn.QueryRow(db.GetContext(), `
				SELECT count() as count FROM conn
			`).ScanStruct(&result)
		require.NoError(t, err, "querying conn table should not produce an error")
		require.Equal(t, uint64(0), result.Count, "number of records in conn table should be 0")

		// validate that number of open conn records is > 0
		err = db.Conn.QueryRow(db.GetContext(), `
				SELECT count() as count FROM openconn
			`).ScanStruct(&result)
		require.NoError(t, err, "querying openconn table should not produce an error")
		require.Greater(t, result.Count, uint64(0), "number of open conn records should be >0")

		// get the min timestamp
		minTS, _, _, _, err := db.GetTrueMinMaxTimestamps()
		require.NoError(t, err, "fetching min timestamp should not produce an error")

		// get the network size (number of unique internal hosts for the past 24 hours)
		networkSize, err := db.GetNetworkSize(minTS)
		require.NoError(t, err, "getting network size should not produce an error")

		// verify the expected network size
		// fmt.Println("Network Size: ", networkSize)
		require.Greater(t, networkSize, uint64(0), "network size should be greater than zero")
		require.Equal(t, uint64(12), networkSize, "network size for test should match expected value")

	})

}
