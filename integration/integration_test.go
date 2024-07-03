package integration_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"

	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

const ConfigPath = "./test_config.hjson"

const TestDataPath = "../test_data"

type (
	DockerInfo struct {
		clickhouseContainer  *clickhouse.ClickHouseContainer
		clickhouseConnection string
	}
	ValidDatasetTestSuite struct {
		suite.Suite
		server       *database.ServerConn
		db           *database.DB
		cfg          *config.Config
		maxTimestamp time.Time
		minTimestamp time.Time
		// useCurrentTime bool
		importResults cmd.ImportResults
	}

	IntegrationTestSuite ValidDatasetTestSuite
)

var dockerInfo DockerInfo

func TestMain(m *testing.M) {
	// err := godotenv.Load("../.env")
	if err := godotenv.Overload("../.env", "./test.env"); err != nil {
		log.Fatal("Error loading .env file")
	}
	err := SetupClickHouse(&dockerInfo)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

// SetupClickHouse creates a ClickHouse container using the test.docker-compose.yml and handles taking it down when complete
func SetupClickHouse(d *DockerInfo) error {
	version := os.Getenv("CLICKHOUSE_VERSION")
	if version == "" {
		return errors.New("CLICKHOUSE_VERSION environment variable not set")
	}
	ctx := context.Background()
	clickHouseContainer, err := clickhouse.RunContainer(ctx,
		testcontainers.WithImage(fmt.Sprintf("clickhouse/clickhouse-server:%s-alpine", version)),
		clickhouse.WithUsername("default"),
		clickhouse.WithPassword(""),
		clickhouse.WithDatabase("default"),
		clickhouse.WithConfigFile(filepath.Join("../deployment/", "config.xml")),
	)
	if err != nil {
		return err
	}

	d.clickhouseContainer = clickHouseContainer
	connectionHost, err := clickHouseContainer.ConnectionHost(ctx)
	if err != nil {
		return err
	}
	d.clickhouseConnection = connectionHost

	return nil
}

func VerifyNonRollingFiles(t *testing.T, logDir string) cmd.HourlyZeekLogs {
	t.Helper()

	fs := afero.NewOsFs()
	// get hourly map of all log files in directory
	// hourlyLogMap, _, err := cmd.GetHourlyLogMap(fs, logDir)
	hourlyLogMap, _, err := cmd.WalkFiles(fs, logDir)
	require.NoError(t, err)

	// ensure that only the first hour contains logs
	for hour := range hourlyLogMap[0] {
		if hour == 0 {
			require.NotEmpty(t, hourlyLogMap[hour], "first hour should contain logs")
		} else {
			require.Empty(t, hourlyLogMap[hour], "hours other than zero hour shouldn't contain logs")
		}
	}

	return hourlyLogMap[0]
}
