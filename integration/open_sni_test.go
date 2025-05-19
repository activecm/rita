package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/viewer"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OpenSNITestSuite ValidDatasetTestSuite

func TestOpenSNI(t *testing.T) {
	openSNISuite := new(OpenSNITestSuite)

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.Env.DBConnection = dockerInfo.clickhouseConnection

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/open_sni", "opensni", false, true)
	require.NoError(t, err)
	openSNISuite.importResults = results

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "opensni", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	_, maxTimestamp, _, _, err := db.GetTrueMinMaxTimestamps()
	require.NoError(t, err)

	openSNISuite.maxTimestamp = maxTimestamp
	openSNISuite.db = db
	openSNISuite.cfg = cfg
	suite.Run(t, openSNISuite)
}

func (it *OpenSNITestSuite) TestThreats() {
	t := it.T()

	sslServerIP := net.ParseIP("104.131.28.214")

	// verify the results of the analysis
	expectedResults := []struct {
		src              string
		dst              string
		fqdn             string
		finalScore       float64
		beaconScore      float64
		totalDuration    float64
		totalBytes       float64
		count            uint64
		proxyCount       uint64
		openCount        uint64
		proxyIPs         []net.IP
		serverIPs        []net.IP
		prevalenceTotal  int64
		portProtoService []string
	}{

		{src: "10.0.0.238", dst: "::", fqdn: "ce7.stearns.org", finalScore: 0.25468, totalDuration: 14737.061150000001, count: 0, proxyCount: 0, openCount: 2, totalBytes: 24106, serverIPs: []net.IP{sslServerIP}, portProtoService: []string{"8443:tcp:ssl"}},
		{src: "10.0.0.238", dst: "::", fqdn: "ce7.stearns.org:8000", finalScore: 0.11993, totalDuration: 7376.718848, count: 0, proxyCount: 0, openCount: 1, totalBytes: 8144, serverIPs: []net.IP{sslServerIP}, portProtoService: []string{"8000:tcp:http"}},
		{src: "10.0.0.238", dst: "34.222.122.143", finalScore: 0.11667, totalDuration: 7200.403186, count: 0, proxyCount: 0, openCount: 1, totalBytes: 2715618, portProtoService: []string{"64590:tcp:"}},
		{src: "10.0.0.238", dst: "52.33.59.39", finalScore: 0.11667, totalDuration: 7200.169165, count: 0, proxyCount: 0, openCount: 1, totalBytes: 4593763, portProtoService: []string{"64004:tcp:"}},
	}

	min, _, _, _, err := it.db.GetTrueMinMaxTimestamps()
	require.NoError(t, err)

	query, params, _ := viewer.BuildResultsQuery(&viewer.Filter{}, 0, 10, min)
	ctx := it.db.QueryParameters(params)
	rows, err := it.db.Conn.Query(ctx, query)
	require.NoError(t, err)

	i := 0
	for rows.Next() {
		require.NotEqualValues(t, len(expectedResults), i, "db results have more rows than the expected results")
		var res viewer.MixtapeResult
		err := rows.ScanStruct(&res)
		require.NoError(t, err)
		require.Equal(t, expectedResults[i].src, res.Src.String(), "source IP should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.Equal(t, expectedResults[i].dst, res.Dst.String(), "destination IP should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.Equal(t, expectedResults[i].fqdn, res.FQDN, "destination FQDN should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.InDelta(t, expectedResults[i].finalScore, res.FinalScore, 0.001, "final score should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.InDelta(t, expectedResults[i].beaconScore, res.BeaconScore, 0.001, "beacon score should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.InDelta(t, expectedResults[i].totalDuration, res.TotalDuration, 0.001, "total duration should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.InDelta(t, expectedResults[i].totalBytes, res.TotalBytes, 0.001, "total bytes should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.EqualValues(t, expectedResults[i].count, res.Count, "count should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.EqualValues(t, expectedResults[i].proxyCount, res.ProxyCount, "proxy count should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.ElementsMatch(t, expectedResults[i].proxyIPs, res.ProxyIPs, "proxy ips should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.ElementsMatch(t, expectedResults[i].proxyIPs, res.ProxyIPs, "server ips should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)
		require.ElementsMatch(t, expectedResults[i].portProtoService, res.PortProtoService, "port proto service tuples should match, src: %s, dst: %s, fqdn: %s", expectedResults[i].src, expectedResults[i].dst, expectedResults[i].fqdn)

		require.InDelta(t, 1, res.Prevalence, 0.001, "prevalence should be 100%")
		require.InDelta(t, -it.cfg.Modifiers.PrevalenceScoreDecrease, res.PrevalenceScore, 0.001, "prevalence score should equal config decrease value")

		year, month, day := res.FirstSeen.Date()
		require.EqualValues(t, 2024, year, "first seen year should match")
		require.EqualValues(t, 01, month, "first seen month should match")
		require.EqualValues(t, 31, day, "first seen day should match")
		require.InDelta(t, 0, res.FirstSeenScore, 0.001, "first seen score should equal 0 for a non-rolling dataset")
		i++
	}
	rows.Close()

	require.EqualValues(t, len(expectedResults), i, "there should be an equal number of expected results")
}
