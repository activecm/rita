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

type ProxyRollingTestSuite ValidDatasetTestSuite

func TestProxyRolling(t *testing.T) {
	proxyRollingSuite := new(ProxyRollingTestSuite)

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.Env.DBConnection = dockerInfo.clickhouseConnection

	require.True(t, cfg.Filtering.FilterExternalToInternal)

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/proxy_rolling", "proxy_rolling", false, true)
	require.NoError(t, err)
	proxyRollingSuite.importResults = results

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "proxy_rolling", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	_, maxTimestamp, _, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	proxyRollingSuite.maxTimestamp = maxTimestamp
	// proxyRollingSuite.useCurrentTime = useCurrentTime
	proxyRollingSuite.db = db
	proxyRollingSuite.cfg = cfg
	suite.Run(t, proxyRollingSuite)
}

func (it *ProxyRollingTestSuite) TestRollingThreats() {
	t := it.T()

	// hour 15
	// 5 threats
	// (beacon)
	// 20% 50% 10.0.0.111 -> img-getpocket.cdn.mozilla.net:443
	//         10.0.0.238 -> 75.75.75.75
	//         10.0.0.238 -> 185.125.190.56
	//         10.0.0.111 -> www.whitehouse.gov:443
	//         10.0.0.111 -> aus5.mozilla.org:443

	// hour 16
	// 2379 threats
	// 33.84% 67.3% 10.0.0.238 -> 75.75.75.75
	// 29.92% 62.4% 10.0.0.111 -> safebrowsing.googleapis.com:443
	// 21.66% 25.8% 10.0.0.111 -> www.google.com 1h14m56s

	// verify that the dataset had multiple imports by checking that there was more than one unique analyzed_at timestamp
	type res struct {
		AnalyzedAt time.Time `ch:"analyzed_at"`
		Count      uint64    `ch:"c"`
	}
	var results []res

	expectedCounts := []uint64{3, 41}

	err := it.db.Conn.Select(it.db.GetContext(), &results, `
		SELECT analyzed_at, count() as c FROM threat_mixtape
		GROUP BY analyzed_at 
		ORDER BY analyzed_at
	`)
	require.NoError(t, err)

	require.Len(t, results, len(expectedCounts))
	require.EqualValues(t, expectedCounts[0], results[0].Count, "first import threat count should match")
	require.EqualValues(t, expectedCounts[1], results[1].Count, "second import threat count should match")

	proxyIP := net.ParseIP("10.0.0.238")
	require.NotNil(t, proxyIP)

	// verify the results of the analysis
	expectedResults := []struct {
		src           string
		dst           string
		fqdn          string
		finalScore    float64
		beaconScore   float64
		totalDuration float64
		totalBytes    float64
		count         uint64
		proxyCount    uint64
		proxyIPs      []net.IP
	}{
		{src: "10.0.0.238", dst: "75.75.75.75", finalScore: 0.18839, beaconScore: 0.673, totalDuration: 595.72157, count: 1160, totalBytes: 319107},
		{src: "10.0.0.111", dst: "::", fqdn: "safebrowsing.googleapis.com:443", finalScore: 0.1492, beaconScore: 0.624, totalDuration: 6.569, count: 46, proxyCount: 46, totalBytes: 308421, proxyIPs: []net.IP{proxyIP}},
	}

	min, _, _, err := it.db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	query, params, _ := viewer.BuildResultsQuery(&viewer.Filter{}, 0, 10, min)
	ctx := it.db.QueryParameters(params)
	rows, err := it.db.Conn.Query(ctx, query)
	require.NoError(t, err)

	i := 0
	for rows.Next() {
		var res viewer.MixtapeResult
		err := rows.ScanStruct(&res)
		require.NoError(t, err)
		if i < len(expectedResults) {
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
		}
		i++
	}
	rows.Close()
}

func (it *ProxyRollingTestSuite) TestProxy() {
	t := it.T()
	var httpProxy, usniProxy, missingMixtapeProxy uint64

	// get number of unique proxy connections from http logs
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count(DISTINCT hash) FROM http
		WHERE method = 'CONNECT'
	`).Scan(&httpProxy)
	require.NoError(t, err)

	// get number of unique connections marked as a proxy conn in usni table
	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count(DISTINCT hash) FROM usni
		WHERE proxy = true
	`).Scan(&usniProxy)
	require.NoError(t, err)

	require.EqualValues(t, httpProxy, usniProxy, "number of proxy connections from http and usni should match")

	// make sure that there are no connections in the mixtape with no proxy count that actually do have proxy connections
	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM (
			SELECT src, host FROM http h
			INNER JOIN threat_mixtape t ON h.src = t.src AND h.host = t.fqdn AND t.proxy_count < 0
			WHERE host != ''
			GROUP BY src, host
			HAVING countIf(method = 'CONNECT') > 0
		)
	`).Scan(&missingMixtapeProxy)
	require.NoError(t, err)

	require.EqualValues(t, 0, missingMixtapeProxy, "there should be no connections in threat_mixtape with missing proxy_counts that are proxy connections")

	var numProxyDst uint64
	// make sure the proxy IP doesn't appear as a destination in the mixtape
	// it should get filtered out by either the conn log filtering or by the SNI conn filtering in the spagooper
	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
		WHERE dst = '10.0.0.238'
	`).Scan(&numProxyDst)
	require.NoError(t, err)

	require.EqualValues(t, 0, numProxyDst, "the proxy IP shouldn't appear as a destination")

}
