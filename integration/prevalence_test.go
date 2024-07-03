package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/activecm/ritav2/cmd"
	"github.com/activecm/ritav2/config"
	"github.com/activecm/ritav2/database"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type prevalenceRes struct {
	PrevTotal       uint64  `ch:"prevalence_total"`
	Prevalence      float32 `ch:"prevalence"`
	PrevalenceScore float32 `ch:"prevalence_score"`
}

func (it *ValidDatasetTestSuite) TestPrevalence() {
	t := it.T()
	var count uint64

	// make sure that there are no invalid prevalence values
	err := it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM threat_mixtape
		WHERE (count > 0 OR beacon_type = 'dns') -- don't check rows where count is 0, bc modifier rows don't contain a count nor the prevalence (DNS threats don't have a count either)
		AND ( prevalence = 0 OR prevalence > 1 )
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count)

	// TODO: check prevalence for specific:
	// ip -> ip
	// ip -> fqdn
	// 216.58.192.130

	var results []prevalenceRes

	err = it.db.Conn.Select(it.db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND dst = '64.4.54.254'
	`)
	require.NoError(t, err)
	networkSize := float32(15)
	for _, r := range results {
		require.EqualValues(t, 13, r.PrevTotal)
		require.InEpsilon(t, 13/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}

	err = it.db.Conn.Select(it.db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND fqdn = 'amplifypixel.outbrain.com'
	`)
	require.NoError(t, err)

	for _, r := range results {
		require.EqualValues(t, 13, r.PrevTotal)
		require.InEpsilon(t, 13/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}

	err = it.db.Conn.Select(it.db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND fqdn = 'amazonaws.com'
	`)
	require.NoError(t, err)

	for _, r := range results {
		require.EqualValues(t, 9, r.PrevTotal)
		require.InEpsilon(t, 9/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}

}

func (it *MissingHostSuite) TestPrevalence() {
	// this dataset only has 1 internal host.
	// the prevalence score for every single connection should be 100%
	// this dataset does not have any C2 over DNS threats, so this test does not cover that
	t := it.T()
	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM threat_mixtape
		WHERE count > 0 -- don't check rows where count is 0, bc modifier rows don't contain a count nor the prevalence (DNS threats don't have a count either)
		AND prevalence != 1
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count)
}

func (it *ProxyRollingTestSuite) TestPrevalence() {
	// this dataset only has 2 internal hosts. one of them is the proxy IP (10.0.0.238)
	// the prevalence score for every single connection should be 50% or 100%
	// this dataset does not have any C2 over DNS threats, so this test does not cover that
	t := it.T()
	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM threat_mixtape
		WHERE count > 0 -- don't check rows where count is 0, bc modifier rows don't contain a count nor the prevalence (DNS threats don't have a count either)
		AND (prevalence = 0 OR prevalence > 1)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no invalid prevalence values")

	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM threat_mixtape
		WHERE proxy_count > 0 and prevalence != 1
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "any connections communicating over proxy should have a prevalence of 100%")

	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM threat_mixtape
		WHERE count > 0 AND proxy_count = 0 AND prevalence != 0.5
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "any connections not communicating over proxy should have a prevalence of 50%")
}

func TestExternalToInternalPrevalence(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.DBConnection = dockerInfo.clickhouseConnection
	cfg.Filter.FilterExternalToInternal = false
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/valid_tsv", "dnscat2_ja3_strobe_external", false, false)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "dnscat2_ja3_strobe_external", cfg, nil)
	require.NoError(t, err)

	var results []prevalenceRes

	networkSize := float32(15)

	// destination that is both the source and destination in conn
	err = db.Conn.Select(db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND dst = '66.218.84.141'
	`)
	require.NoError(t, err)

	for _, r := range results {
		require.EqualValues(t, 9, r.PrevTotal)
		require.InEpsilon(t, 9/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}

	err = db.Conn.Select(db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND fqdn = 'amplifypixel.outbrain.com'
	`)
	require.NoError(t, err)

	for _, r := range results {
		require.EqualValues(t, 13, r.PrevTotal)
		require.InEpsilon(t, 13/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}

	err = db.Conn.Select(db.GetContext(), &results, `--sql
		SELECT prevalence_total, prevalence, prevalence_score FROM threat_mixtape
		WHERE count > 0 AND fqdn = 'amazonaws.com'
	`)
	require.NoError(t, err)

	for _, r := range results {
		require.EqualValues(t, 9, r.PrevTotal)
		require.InEpsilon(t, 9/networkSize, r.Prevalence, 0.001)
		require.InEpsilon(t, -0.15, r.PrevalenceScore, 0.001)
	}
}
