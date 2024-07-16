package cmd_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"

	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	cl "github.com/testcontainers/testcontainers-go/modules/clickhouse"
	"github.com/urfave/cli/v2"
)

const ConfigPath = "../integration/test_config.hjson"

const TestDataPath = "../test_data"

type CmdTestSuite struct {
	suite.Suite
	cfg                  *config.Config
	clickhouseContainer  *cl.ClickHouseContainer
	clickhouseConnection string
	server               *database.ServerConn
}

func TestMain(m *testing.M) {
	// load environment variables with panic prevention
	if err := godotenv.Overload("../.env", "../integration/test.env"); err != nil {
		log.Fatalf("error loading .env file: %v", err)
	}

	// set version
	config.Version = ""

	// run the tests
	os.Exit(m.Run())
}

func TestCmdTestSuite(t *testing.T) {
	suite.Run(t, new(CmdTestSuite))
}

// SetupSuite is run once before the first test starts
func (c *CmdTestSuite) SetupSuite() {
	t := c.T()

	// set up file system interface
	afs := afero.NewOsFs()

	// load the config file
	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err, "config should load without error")

	// // set version
	// config.Version = ""

	// start clickhouse container
	c.SetupClickHouse(t)

	// update the config to use the clickhouse container connection
	cfg.DBConnection = c.clickhouseConnection
	cfg.UpdateCheckEnabled = false
	c.cfg = cfg

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), cfg)
	require.NoError(t, err, "connecting to server should not produce an error")
	c.server = server
}

// TearDownSuite is run once after all tests have finished
func (c *CmdTestSuite) TearDownSuite() {
	if err := c.clickhouseContainer.Terminate(context.Background()); err != nil {
		log.Fatalf("failed to terminate clickhouse container: %s", err)
	}
}

// SetupTest is run before each test method
// func (d *DatabaseTestSuite) SetupTest() {}

// TearDownTest is run after each test method
// func (d *DatabaseTestSuite) TearDownTest() {}

// SetupSubTest is run before each subtest
func (c *CmdTestSuite) SetupSubTest() {
	t := c.T()
	fmt.Println("Running setup subtest...")

	// drop all databases that may have been created during subtest
	if c.server != nil && c.server.Conn != nil {
		dbs, err := c.server.ListImportDatabases()
		require.NoError(t, err, "listing databases should not produce an error")
		for _, db := range dbs {
			err := c.server.DeleteSensorDB(db.Name)
			require.NoError(t, err, "dropping database should not produce an error")
		}
	}
}

// TearDownSubTest is run after each subtest
// func (c *CmdTestSuite) TearDownSubTest() {}

// SetupClickHouse creates a ClickHouse container using the test.docker-compose.yml and handles taking it down when complete
func (c *CmdTestSuite) SetupClickHouse(t *testing.T) {
	t.Helper()
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
	c.clickhouseContainer = clickHouseContainer
	c.clickhouseConnection = connectionHost

}

func setupTestApp(commands []*cli.Command, flags []cli.Flag) (*cli.App, context.Context) {
	ctx := context.Background()

	app := cli.NewApp()
	app.Args = true
	app.Commands = commands
	app.Flags = flags

	// custom exit handler to override the default which calls os.Exit
	// this prevents the test from exiting when testing for errors
	app.ExitErrHandler = func(_ *cli.Context, _ error) {
		// add any custom test logic, or assertions or leave it blank

	}

	return app, ctx
}
