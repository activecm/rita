package database_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	cl "github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

const ConfigPath = "../integration/test_config.hjson"

const TestDataPath = "../test_data"

type DatabaseTestSuite struct {
	suite.Suite
	cfg                  *config.Config
	clickhouseContainer  *cl.ClickHouseContainer
	clickhouseConnection string
	server               *database.ServerConn
}

func TestMain(m *testing.M) {
	// load environment variables with panic prevention
	if err := godotenv.Overload("../.env", "../integration/test.env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	os.Exit(m.Run())
}

func TestDatabase(t *testing.T) {
	suite.Run(t, new(DatabaseTestSuite))
}

// SetupSuite is run once before the first test starts
func (d *DatabaseTestSuite) SetupSuite() {
	t := d.T()

	// load the config file
	cfg, err := config.LoadConfig(afero.NewOsFs(), ConfigPath)
	require.NoError(t, err, "config should load without error")

	// start clickhouse container
	d.SetupClickHouse(t)

	// update the config to use the clickhouse container connection
	cfg.DBConnection = d.clickhouseConnection

	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "config should update without error")
	d.cfg = cfg

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), d.cfg)
	require.NoError(t, err, "connecting to server should not produce an error")
	d.server = server
}

// TearDownSuite is run once after all tests have finished
func (d *DatabaseTestSuite) TearDownSuite() {
	if err := d.clickhouseContainer.Terminate(context.Background()); err != nil {
		log.Fatalf("failed to terminate clickhouse container: %s", err)
	}
}

// SetupTest is run before each test method
// func (d *DatabaseTestSuite) SetupTest() {}

// TearDownTest is run after each test method
// func (d *DatabaseTestSuite) TearDownTest() {}

// SetupSubTest is run before each subtest
func (d *DatabaseTestSuite) SetupSubTest() {
	t := d.T()
	// fmt.Println("Running setup subtest...")

	// drop all databases that may have been created during subtest
	if d.server != nil && d.server.Conn != nil {
		dbs, err := d.server.ListImportDatabases()
		require.NoError(t, err, "listing databases should not produce an error")
		for _, db := range dbs {
			err := d.server.DeleteSensorDB(db.Name)
			require.NoError(t, err, "dropping database should not produce an error")
		}
	}
}

// TearDownSubTest is run after each subtest
// func (d *DatabaseTestSuite) TearDownSubTest() {}

// SetupClickHouse creates a ClickHouse container using the test.docker-compose.yml and handles taking it down when complete
func (d *DatabaseTestSuite) SetupClickHouse(t *testing.T) {
	t.Helper()

	// get ClickHouse version from environment
	version := os.Getenv("CLICKHOUSE_VERSION")
	require.NotEmpty(t, version, "CLICKHOUSE_VERSION environment variable must be set")

	// create ClickHouse container
	ctx := context.Background()
	clickHouseContainer, err := cl.RunContainer(ctx,
		testcontainers.WithImage(fmt.Sprintf("clickhouse/clickhouse-server:%s-alpine", version)),
		cl.WithUsername("default"),
		cl.WithPassword(""),
		cl.WithDatabase("default"),
		cl.WithConfigFile(filepath.Join("../deployment/", "config.xml")),
	)
	require.NoError(t, err, "failed to start clickHouse container")

	// get connection host
	connectionHost, err := clickHouseContainer.ConnectionHost(ctx)
	require.NoError(t, err, "failed to get clickHouse connection host")

	// set container and connection host
	d.clickhouseContainer = clickHouseContainer
	d.clickhouseConnection = connectionHost

}

func (d *DatabaseTestSuite) TestConnectToServer() {

	// connect to the server with valid configuration
	d.Run("Successful Server Connection", func() {
		t := d.T()
		server, err := database.ConnectToServer(context.Background(), d.cfg)
		require.NoError(t, err, "connecting to clickhouse server should not produce an error")
		require.NotNil(t, server, "server connection object should not be nil")

		// ping to ensure the connection is valid
		err = server.Conn.Ping(context.Background())
		require.NoError(t, err, "pinging clickhouse server should not produce an error")
	})

	// attempt to connect with invalid configuration
	d.Run("Failed Server Connection", func() {
		t := d.T()
		invalidCfg := *d.cfg
		invalidCfg.DBConnection = "invalid connection string"

		server, err := database.ConnectToServer(context.Background(), &invalidCfg)
		require.Error(t, err, "connecting with invalid configuration should produce an error")
		require.Nil(t, server, "server connection object should be nil on failed connection")
	})
}

func (d *DatabaseTestSuite) TestDeleteSensorDB() {
	d.Run("Drop Existing Database", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		db, err := database.ConnectToDB(context.Background(), "testDB", d.cfg, nil)
		require.NoError(t, err, "connecting to created database should not produce an error")
		require.NotNil(t, db)

		// drop the database
		err = d.server.DeleteSensorDB("testDB")
		require.NoError(t, err, "dropping database should not produce an error")

		d.checkDatabaseDeletion("testDB")
	})

	d.Run("Drop Non-Existent Database", func() {
		t := d.T()

		// attempt to drop a database that doesn't exist
		err := d.server.DeleteSensorDB("nonExistentDB")
		require.NoError(t, err, "attempting to drop a non-existent database should not produce an error")
	})

}

func (d *DatabaseTestSuite) checkDatabaseDeletion(dbName string) {
	t := d.T()
	// attempt to connect to the dropped database
	db, err := database.ConnectToDB(context.Background(), dbName, d.cfg, nil)
	require.Error(t, err, "connecting to a dropped database should produce an error")
	require.Nil(t, db)
	ctx := d.server.QueryParameters(clickhouse.Parameters{
		"database": dbName,
	})
	// check for db in min_max
	var count uint64
	err = d.server.Conn.QueryRow(ctx, `
		SELECT count() FROM metadatabase.min_max
		WHERE database = {database:String}
	`).Scan(&count)
	require.NoError(t, err, "querying metadatabase.min_max should not produce an error")
	require.EqualValues(t, 0, count, "there should be no records for a deleted dataset in metadatabase.min_max, database: %s", dbName)
	// check for db in files
	err = d.server.Conn.QueryRow(ctx, `
		SELECT count() FROM metadatabase.files
		WHERE database = {database:String}
	`).Scan(&count)
	require.NoError(t, err, "querying metadatabase.files should not produce an error")
	require.EqualValues(t, 0, count, "there should be no records for a deleted dataset in metadatabase.files, database: %s", dbName)
}

func (d *DatabaseTestSuite) checkDatabaseNonDeletion(dbName string) {
	t := d.T()
	// attempt to connect to the database
	db, err := database.ConnectToDB(context.Background(), dbName, d.cfg, nil)
	require.NoError(t, err, "connecting to a database that was not dropped should not produce an error")
	require.NotNil(t, db)
	ctx := d.server.QueryParameters(clickhouse.Parameters{
		"database": dbName,
	})
	// check for db in min_max
	var count uint64
	err = d.server.Conn.QueryRow(ctx, `
		SELECT count() FROM metadatabase.min_max
		WHERE database = {database:String}
	`).Scan(&count)
	require.NoError(t, err, "querying metadatabase.min_max should not produce an error")
	require.Greater(t, count, uint64(0), "there should be at least 1 record for a dataset in metadatabase.min_max, database: %s", dbName)
	// check for db in files
	err = d.server.Conn.QueryRow(ctx, `
		SELECT count() FROM metadatabase.files
		WHERE database = {database:String}
	`).Scan(&count)
	require.NoError(t, err, "querying metadatabase.files should not produce an error")
	require.Greater(t, count, uint64(0), "there should be at least 1 record for a dataset in metadatabase.files, database: %s", dbName)
}

func (d *DatabaseTestSuite) TestDropMultipleSensorDatabases() {
	// helper function to create databases with various prefixes and suffixes
	databases := []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"}

	createDatabases := func(t *testing.T) {
		t.Helper()

		for _, dbName := range databases {
			// create a database name with no prefix or suffix
			_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", dbName, false, false)
			require.NoError(t, err, "importing data should not produce an error")

		}
	}

	d.Run("Drop Databases with Prefix Wildcard", func() {
		t := d.T()

		// create the databases
		createDatabases(t)

		deleted := databases[:2]
		notDeleted := databases[2:]
		// drop databases with a prefix wildcard
		numDeleted, err := d.server.DropMultipleSensorDatabases("bingbong", true, false)
		require.NoError(t, err, "dropping databases with prefix wildcard should not produce an error")
		require.Equal(t, 2, numDeleted, "should delete exactly 2 databases") // should match the first two databases created

		for _, dbName := range deleted {
			d.checkDatabaseDeletion(dbName)
		}

		for _, dbName := range notDeleted {
			d.checkDatabaseNonDeletion(dbName)
		}
	})

	d.Run("Drop Databases with Suffix Wildcard", func() {
		t := d.T()
		// create the databases
		createDatabases(t)

		deleted := []string{databases[0], databases[2]}
		notDeleted := []string{databases[1], databases[3]}
		// drop databases with a suffix wildcard
		numDeleted, err := d.server.DropMultipleSensorDatabases("bingbong", false, true)
		require.NoError(t, err, "dropping databases with suffix wildcard should not produce an error")
		require.Equal(t, 2, numDeleted, "should delete exactly 2 databases") // should match the first and third databases created

		for _, dbName := range deleted {
			d.checkDatabaseDeletion(dbName)
		}

		for _, dbName := range notDeleted {
			d.checkDatabaseNonDeletion(dbName)
		}
	})

	d.Run("Drop Databases with Both Wildcards", func() {
		t := d.T()
		// create the databases
		createDatabases(t)

		// drop databases with both wildcards
		numDeleted, err := d.server.DropMultipleSensorDatabases("bingbong", true, true)
		require.NoError(t, err, "dropping databases with both wildcards should not produce an error")
		require.Equal(t, 4, numDeleted, "should delete all databases matching the wildcard pattern") // should match all databases created

		for _, dbName := range databases {
			d.checkDatabaseDeletion(dbName)
		}
	})

	d.Run("Drop Databases with No Wildcards", func() {
		t := d.T()
		// create the databases
		createDatabases(t)

		// drop databases without wildcards
		numDeleted, err := d.server.DropMultipleSensorDatabases("bingbong", false, false)
		require.Error(t, err, "dropping databases without specifying a wildcard should produce an error")
		require.Equal(t, 0, numDeleted, "no databases should be deleted if no wildcard is specified")
		for _, dbName := range databases {
			d.checkDatabaseNonDeletion(dbName)
		}
	})
}

func (d *DatabaseTestSuite) TestListImportDatabases() {
	d.Run("List Databases", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, true)
		require.NoError(t, err, "importing data should not produce an error")
		_, err = cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB2", false, true)
		require.NoError(t, err, "importing data should not produce an error")

		dbs, err := d.server.ListImportDatabases()
		require.NoError(t, err, "listing databases should not produce an error")
		require.Len(t, dbs, 2, "two databases should be listed")
		dbString := database.GetFlatDatabaseList(dbs)

		require.Containsf(t, dbString, "testDB", "testDB should be listed")
		require.Contains(t, dbString, "testDB2", "testDB2 should be listed")
	})

	d.Run("No Databases", func() {
		t := d.T()
		dbs, err := d.server.ListImportDatabases()
		require.NoError(t, err, "listing databases should not produce an error")
		require.Nil(t, dbs, "databases should be nil")
	})

	d.Run("Missing Metadatabase", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		err = d.server.Conn.Exec(context.Background(), "DROP DATABASE IF EXISTS metadatabase")
		require.NoError(t, err, "dropping metadatabase should not produce an error")

		dbs, err := d.server.ListImportDatabases()
		require.NoError(t, err, "listing databases with missing metadatabase should not produce an error")
		require.Nil(t, dbs, "databases should be nil")
	})
}

func (d *DatabaseTestSuite) TestGetRollingStatus() {
	d.Run("Get Status of Rolling Database", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", true, false)
		require.NoError(t, err, "importing data should not produce an error")

		status, err := database.GetRollingStatus(context.Background(), d.server.Conn, "testDB")
		require.NoError(t, err, "getting status of rolling database should not produce an error")
		fmt.Print("status: ", status)
		require.True(t, status, "status of rolling database should be true")
	})

	d.Run("Get Status of Non-Rolling Database", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		status, err := database.GetRollingStatus(context.Background(), d.server.Conn, "testDB")
		require.NoError(t, err, "getting status of non-rolling database should not produce an error")
		require.False(t, status, "status of non-rolling database should be false")
	})

	d.Run("Get Status of Non-Existent Database", func() {
		t := d.T()
		status, err := database.GetRollingStatus(context.Background(), d.server.Conn, "testDB")
		require.Error(t, err, "getting status of non-existent database should produce an error")
		require.Equal(t, err, database.ErrDatabaseNotFound, "error should be database not found")
		require.False(t, status, "status of non-existent database should be false")
	})

}

func (d *DatabaseTestSuite) TestDatabaseExists() {
	d.Run("Database Exists", func() {
		t := d.T()
		_, err := cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "testDB", false, false)
		require.NoError(t, err, "importing data should not produce an error")

		exists, err := database.DatabaseExists(d.server.Conn, context.Background(), "testDB")
		require.NoError(t, err, "checking if database exists should not produce an error")
		require.True(t, exists, "database should exist")
	})

	d.Run("Database Does Not Exist", func() {
		t := d.T()
		exists, err := database.DatabaseExists(d.server.Conn, context.Background(), "testDB")
		require.NoError(t, err, "checking if database exists should not produce an error")
		require.False(t, exists, "database should not exist")
	})
}
