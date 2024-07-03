package integration_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/activecm/ritav2/cmd"
	"github.com/activecm/ritav2/config"
	"github.com/activecm/ritav2/database"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ThreatIntelSuite FilterTestSuite

func TestThreatIntel(t *testing.T) {
	suite.Run(t, new(ThreatIntelSuite))
}

// Reset config after each test since these tests load the config from a file
func (it *ThreatIntelSuite) SetupSuite() {
	afs := afero.NewOsFs()
	cfg, err := config.LoadConfig(afs, ConfigPath)
	it.Require().NoError(err)
	it.cfg = cfg
}

func (it *ThreatIntelSuite) SetupTest() {
	err := it.cfg.ResetConfig()
	it.Require().NoError(err)
}

func (it *ThreatIntelSuite) TearDownSuite() {
	err := it.cfg.ResetConfig()
	it.Require().NoError(err)
}

func (it *ThreatIntelSuite) TestFileFeeds() {
	t := it.T()
	dbName := "threat_intel_file_feed"

	// set up file system interface
	afs := afero.NewMemMapFs()

	err := afero.WriteFile(afs, "threat_intel_config.hjson", []byte(`
	{
		filtering: {
			filter_external_to_internal: false,
			internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
		},
		threat_intel: {
			online_feeds: ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
			custom_feeds_directory: "./threat_intel_feeds"
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.LoadConfig(afs, "threat_intel_config.hjson")
	require.NoError(t, err)
	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")
	it.cfg = cfg

	fs := afero.NewOsFs()
	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, fs, "../test_data/valid_json", dbName, false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), dbName, cfg, nil)
	require.NoError(t, err)

	checkThreatIntel(t, db)
}

func (it *ThreatIntelSuite) TestOnlineFeeds() {
	t := it.T()
	dbName := "threat_intel_online_feed"
	t.SkipNow()
	// Get current commit hash
	gitCmd := exec.Command("git", "rev-parse", "HEAD")
	stdout, err := gitCmd.Output()
	require.NoError(t, err)
	commitHash := strings.TrimSpace(string(stdout))
	require.NotEmpty(t, commitHash)

	// Get online feed by pulling the file feed from Github
	feedURL := "https://github.com/activecm/rita/blob/" + commitHash + "/integration/threat_intel_feeds/feed.txt"

	// set up file system interface
	afs := afero.NewMemMapFs()
	configStr := `
		{
			filtering: {
				filter_external_to_internal: false,
				internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
			},
			threat_intel: {
				online_feeds: ["%s"],
				custom_feeds_directory: "../deployment/threat_intel_feeds" // remove custom feed
			},
			http_extensions_file_path: "../deployment/http_extensions_list.csv"
		}
	`
	err = afero.WriteFile(afs, "threat_intel_config.hjson", []byte(fmt.Sprintf(configStr, feedURL)), 0755)
	require.NoError(t, err)

	cfg, err := config.LoadConfig(afs, "threat_intel_config.hjson")
	require.NoError(t, err)
	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)

	require.Contains(t, cfg.ThreatIntel.OnlineFeeds, feedURL)
	require.NoError(t, err, "updating config should not return an error")
	it.cfg = cfg

	fs := afero.NewOsFs()
	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, fs, "../test_data/valid_json", dbName, false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), dbName, cfg, nil)
	require.NoError(t, err)

	checkThreatIntel(t, db)
}

func checkThreatIntel(t *testing.T, db *database.DB) {
	t.Helper()
	var count uint64

	// verify that all r-1x threats are marked
	err := db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
		WHERE fqdn = 'r-1x.com' AND threat_intel = true
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "there should be 1 entry on threat intel from 'r-1x.com', got: %d", count)

	// verify that 165.227.88.15 threats are marked
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
		WHERE dst = '165.227.88.15' AND threat_intel = true
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "there should be 1 entry on threat intel from '165.227.88.15', got: %d", count)

	// verify that 24.220.113.36 threats are marked
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
		WHERE dst = '24.220.113.36' AND threat_intel = true
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 2, count, "there should be 2 entries on threat intel from '24.220.113.36', got: %d", count)

	// verify that all 0.gravatar.com threats are marked
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
		WHERE fqdn = '0.gravatar.com' AND threat_intel = true
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 2, count, "there should be 2 entries on threat intel from '0.gravatar.com', got: %d", count)
}
