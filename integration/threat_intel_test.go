package integration_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/internal/testutils"

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
	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	it.Require().NoError(err)
	it.cfg = cfg
}

func (it *ThreatIntelSuite) SetupTest() {
	err := it.cfg.Reset()
	it.Require().NoError(err)
}

func (it *ThreatIntelSuite) TearDownSuite() {
	err := it.cfg.Reset()
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
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.ReadFileConfig(afs, "threat_intel_config.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	cfg.Env.ThreatIntelCustomFeedsDirectory = "./threat_intel_feeds"
	it.cfg = cfg

	fs := afero.NewOsFs()
	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, fs, "../test_data/valid_json", dbName, false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), dbName, cfg, nil)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
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

	cfg, err := config.ReadFileConfig(afs, "threat_intel_config.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	require.Contains(t, cfg.RITA.ThreatIntel.OnlineFeeds, feedURL)
	it.cfg = cfg

	fs := afero.NewOsFs()
	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, fs, "../test_data/valid_json", dbName, false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), dbName, cfg, nil)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	require.NoError(t, err)

	checkThreatIntel(t, db)
}

func (d *ThreatIntelSuite) TestThreatIntelFeedFilesClosing() {
	t := d.T()

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), d.cfg)
	t.Cleanup(func() {
		require.NoError(t, server.Close())
	})
	require.NoError(t, err, "connecting to server should not produce an error")

	require.NoError(t, server.CreateServerDBTables(), "creating the metadatabase should not error")

	const numFeeds = 64

	feedDir := t.TempDir()
	// make the time for the first round unique from the second round
	firstRound := time.Now().Add(-2 * time.Hour)
	makeFakeThreatIntelFeeds(t, feedDir, numFeeds, "192.0.2", firstRound)

	// temporarily override the threat intel config
	originalDir := d.cfg.Env.ThreatIntelCustomFeedsDirectory
	originalFeeds := d.cfg.RITA.ThreatIntel.OnlineFeeds
	d.cfg.Env.ThreatIntelCustomFeedsDirectory = feedDir
	d.cfg.RITA.ThreatIntel.OnlineFeeds = nil
	t.Cleanup(func() {
		d.cfg.Env.ThreatIntelCustomFeedsDirectory = originalDir
		d.cfg.RITA.ThreatIntel.OnlineFeeds = originalFeeds
	})

	afs := testutils.NewCountingFS(afero.NewOsFs())

	require.NoError(t, server.SyncThreatIntelFeedsFromConfig(afs, d.cfg), "adding new feeds should not error")

	opened, closed := afs.GetCounts()
	require.GreaterOrEqual(t, opened, numFeeds, "the sync should have opened every fake feed")
	require.Equal(t, opened, closed, "adding feeds left %d of %d files still open", opened-closed, opened)
	require.EqualValues(t, numFeeds, d.threatIntelEntryCount(t, server, "192.0.2.0", "192.0.2.255"),
		"every new feed's entries should be in the database after the first sync")

	makeFakeThreatIntelFeeds(t, feedDir, numFeeds, "203.0.113", firstRound.Add(time.Hour))

	openedBefore := opened
	require.NoError(t, server.SyncThreatIntelFeedsFromConfig(afs, d.cfg), "updating modified feeds should not error")

	opened, closed = afs.GetCounts()
	require.GreaterOrEqual(t, opened-openedBefore, numFeeds, "running the sync again should have reopened every modified feed")
	require.Equal(t, opened, closed, "updating feeds left %d of %d files still open", opened-closed, opened)

	// if a feed closed before the parser reads it, it doesn't make it into the db
	// make sure the entries from the second sync are in the metadatabase
	require.EqualValues(t, numFeeds, d.threatIntelEntryCount(t, server, "203.0.113.0", "203.0.113.255"),
		"modified feed's entries should be in the database after the second sync")
}

func (d *ThreatIntelSuite) threatIntelEntryCount(t *testing.T, server *database.ServerConn, from, to string) uint64 {
	t.Helper()

	var count uint64
	err := server.Conn.QueryRow(server.GetContext(), `
		SELECT count() FROM metadatabase.threat_intel
		WHERE ip BETWEEN toIPv6($1) AND toIPv6($2)
	`, from, to).Scan(&count)
	require.NoError(t, err, "counting threat intel entries should not error")
	return count
}

func makeFakeThreatIntelFeeds(t *testing.T, dir string, count int, prefix string, modTime time.Time) {
	t.Helper()
	for i := 1; i <= count; i++ {
		path := filepath.Join(dir, fmt.Sprintf("feed_%02d.txt", i))
		body := fmt.Sprintf("# staged threat intel feed %d\n%s.%d\n", i, prefix, i)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		require.NoError(t, os.Chtimes(path, modTime, modTime))
	}
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
