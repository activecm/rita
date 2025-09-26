package viewer_test

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
	"github.com/activecm/rita/v5/viewer"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

const ConfigPath = "../integration/test_config.hjson"

type ViewerTestSuite struct {
	suite.Suite
	db                   *database.DB
	maxTimestamp         time.Time
	minTimestamp         time.Time
	useCurrentTime       bool
	clickhouseContainer  *clickhouse.ClickHouseContainer
	clickhouseConnection string
}

func (s *ViewerTestSuite) SetupSuite() {
	t := s.T()

	// load environment variables
	err := godotenv.Overload("../.env", "../integration/test.env")
	require.NoError(t, err, "cannot load .env file")

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)

	s.SetupClickHouse(t)

	cfg.Env.DBConnection = s.clickhouseConnection

	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/valid_tsv", "dnscat2_ja3_strobe", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "dnscat2_ja3_strobe", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	minTimestamp, maxTimestamp, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
	require.NoError(t, err)

	s.maxTimestamp = maxTimestamp
	s.minTimestamp = minTimestamp
	s.useCurrentTime = useCurrentTime
	s.db = db
}

// SetupClickHouse creates a ClickHouse container using the test.docker-compose.yml and handles taking it down when complete
func (s *ViewerTestSuite) SetupClickHouse(t *testing.T) {
	t.Helper()

	version := os.Getenv("CLICKHOUSE_VERSION")
	require.NotEmpty(t, version, "CLICKHOUSE_VERSION environment variable must be set")

	ctx := context.Background()
	clickHouseContainer, err := clickhouse.RunContainer(ctx,
		testcontainers.WithImage(fmt.Sprintf("clickhouse/clickhouse-server:%s-alpine", version)),
		clickhouse.WithUsername("default"),
		clickhouse.WithPassword(""),
		clickhouse.WithDatabase("default"),
		clickhouse.WithConfigFile(filepath.Join("../deployment/", "config.xml")),
	)
	require.NoError(t, err)

	s.clickhouseContainer = clickHouseContainer
	connectionHost, err := clickHouseContainer.ConnectionHost(ctx)
	require.NoError(t, err)
	s.clickhouseConnection = connectionHost

}

func TestViewer(t *testing.T) {
	viewerSuite := new(ViewerTestSuite)
	suite.Run(t, viewerSuite)
}

func (s *ViewerTestSuite) TearDownSuite() {
	if err := s.clickhouseContainer.Terminate(context.Background()); err != nil {
		log.Fatalf("failed to terminate container: %s", err)
	}
}

func (s *ViewerTestSuite) TestViewerUpdate() {
	t := s.T()
	require := require.New(t)

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(err)

	// toggle help on
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	require.True(m.ViewHelp, "expected help to be toggled on, got off")

	// toggle help off
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	require.False(m.ViewHelp, "expected help to be toggled off, got on")

	// toggle sidebar scrolling to be enabled
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	require.True(m.SideBar.ScrollEnabled, "expected sidebar scrolling to be enabled, got disabled")

	// toggle sidebar scrolling to be disabled
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	require.False(m.SideBar.ScrollEnabled, "expected sidebar scrolling to be disabled, got enabled")

	// toggle search bar focus
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	require.True(m.SearchBar.TextInput.Focused(), "expected search bar to be focused, got unfocused")

	// toggle search bar help on
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	require.True(m.ViewSearchHelp, "expected search bar help to be toggled on, got off")

	// toggle search bar help off
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	require.False(m.ViewSearchHelp, "expected search bar help to be toggled off, got on")

	// toggle search bar help back on so that we can make sure that unfocusing the search bar will also turn off the search bar help
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	require.True(m.ViewSearchHelp, "expected search bar help to be toggled on, got off")

	// toggle search bar focus off
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.False(m.ViewSearchHelp, "expected search bar help to be toggled off, got on")
	require.False(m.SearchBar.TextInput.Focused(), "expected search bar to be unfocused, got focused")

	// quit the program with 'q'
	_, command := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	fmt.Printf("cmd: %v\n", command)
	require.Equal(tea.Quit(), command(), "expected quit command, got %v", command)

	// quit the program with ctrl+c
	_, command = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	fmt.Printf("cmd: %v\n", command)
	require.Equal(tea.Quit(), command(), "expected quit command, got %v", command)

}
