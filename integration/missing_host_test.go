package integration_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/activecm/ritav2/cmd"
	"github.com/activecm/ritav2/config"
	"github.com/activecm/ritav2/database"
	"github.com/activecm/ritav2/viewer"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

/*
All interesting traffic is coming from 73.54.23.243 to 64.225.56.201
The zeek sensor was running on 64.225.56.201

The logs contain the following data:
3 days worth of log files
An SSH session that is open the entire time
An HTTP connection with a blank "Host:" parameter
It has a unique user agent string of "'Modzilla/0.0001 (Atari 7800)'"
HTTP connection is beaconing every 200-350 seconds

Last 24 hours
73.54.23.243 to 64.225.56.201
count: 331
missing host header: 330x
rare signature modifier: Modzilla/0.0001 (Atari 7800)

Connections not in the last import
172.70.114.7        fomobasedcoin.com
64.225.56.201       venomlaunchpad.com

*/

type MissingHostSuite ValidDatasetTestSuite

func TestMissingHost(t *testing.T) {
	missingHostSuite := new(MissingHostSuite)

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	_, dropletSubnet, err := net.ParseCIDR("64.225.56.201/32")
	require.NoError(t, err)
	cfg.Filter.InternalSubnets = append(cfg.Filter.InternalSubnets, dropletSubnet)
	cfg.Filter.FilterExternalToInternal = false
	err = config.UpdateConfig(cfg)

	cfg.DBConnection = dockerInfo.clickhouseConnection
	require.NoError(t, err, "updating config should not return an error")

	require.Contains(t, cfg.Filter.InternalSubnets, &net.IPNet{IP: net.IP{64, 225, 56, 201}, Mask: net.IPMask{255, 255, 255, 255}})
	require.False(t, cfg.Filter.FilterExternalToInternal)

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/missing_host", "missing_host", false, true)
	require.NoError(t, err)
	missingHostSuite.importResults = results
	require.Len(t, results.ImportID, 72, "there should be 72 hours of imports, each with their own unique import ID")

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "missing_host", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	minTimestamp, maxTimestamp, _, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	missingHostSuite.maxTimestamp = maxTimestamp
	missingHostSuite.minTimestamp = minTimestamp

	missingHostSuite.db = db
	missingHostSuite.cfg = cfg
	suite.Run(t, missingHostSuite)
}

// TestThreat verifies the results of the important connection pair in this dataset
func (it *MissingHostSuite) TestThreat() {
	t := it.T()
	// verify the results of the analysis
	type expectedResults struct {
		src              string
		dst              string
		finalScore       float32
		beaconScore      float32
		longConnScore    float32
		totalDuration    float64
		totalBytes       float64
		count            uint64
		missingHostCount uint64
		missingHostScore float32
		prevalence       float32
		portProtoService []string
		firstSeen        time.Time
	}
	expected := expectedResults{
		src: "73.54.23.243", dst: "64.225.56.201",
		finalScore: 1.05, beaconScore: 0.963, longConnScore: config.HIGH_CATEGORY_SCORE,
		totalDuration: 270036.631115, count: 331, missingHostCount: 330, missingHostScore: 0.1,
		totalBytes: 1679442, portProtoService: []string{"80:tcp:http", "22:tcp:ssh"}, prevalence: 1,
		firstSeen: time.Unix(1713470872, 0).UTC(),
	}

	min, max, _, err := it.db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	const predictedStaticMinTS = 1713657591
	const predictedStaticMaxTS = 1713743991

	require.EqualValues(t, time.Unix(predictedStaticMinTS, 0).UTC(), min, "the min timestamp from GetMinMaxTimestamps should match the expected timestamp")
	require.EqualValues(t, time.Unix(predictedStaticMaxTS, 0).UTC(), max, "the max timestamp from GetMinMaxTimestamps should match the expected timestamp")

	var count uint64
	ctx := it.db.QueryParameters(clickhouse.Parameters{
		"min_ts": fmt.Sprintf("%d", time.Unix(predictedStaticMinTS, 0).UTC().Unix()),
		"src":    expected.src,
		"dst":    expected.dst,
	})

	err = it.db.Conn.QueryRow(ctx, `--sql
		select countIf(missing_host_header = false) from conn
		where src = {src:String} and dst = {dst:String}
		and toStartOfHour(ts) >= toStartOfHour(fromUnixTimestamp({min_ts:Int64}))
	`).Scan(&count)
	require.NoError(t, err, "retrieving the connection count should not error")

	require.EqualValues(t, expected.count, count, "the number of connections from the conn table should match, expected: %d, got: %d ", expected.count, count)

	filter := viewer.Filter{Src: expected.src, Dst: expected.dst}
	min = time.Unix(0, 0)
	query, params, _ := viewer.BuildResultsQuery(filter, 0, 10, min)
	ctx = it.db.QueryParameters(params)
	rows, err := it.db.Conn.Query(ctx, query)
	require.NoError(t, err, "getting the mixtape results shouldn't error")

	i := 0
	for rows.Next() {
		var res viewer.MixtapeResult
		err := rows.ScanStruct(&res)
		require.NoError(t, err)
		require.Equal(t, expected.src, res.Src.String(), "source IP should match")
		require.Equal(t, expected.dst, res.Dst.String(), "destination IP should match")
		require.InDelta(t, expected.finalScore, res.FinalScore, 0.001, "final score should match")
		require.InDelta(t, expected.beaconScore, res.BeaconScore, 0.001, "beacon score should match")
		require.InDelta(t, expected.longConnScore, res.LongConnScore, 0.001, "long connection score should match")
		require.InDelta(t, expected.totalDuration, res.TotalDuration, 0.01, "total duration should match")
		require.InDelta(t, expected.totalBytes, res.TotalBytes, 0.001, "total bytes should match")
		require.EqualValues(t, expected.count, res.Count, "count should match")
		require.EqualValues(t, expected.missingHostCount, res.MissingHostCount, "missing host count should match")
		require.InDelta(t, expected.missingHostScore, res.MissingHostHeaderScore, 0.001, "missing host score should match")
		require.InDelta(t, expected.prevalence, res.Prevalence, 0.001, "prevalence should match")
		require.InDelta(t, -it.cfg.Modifiers.PrevalenceScoreDecrease, res.PrevalenceScore, 0.001, "prevalence score should equal the prevalence decrease config value")
		require.InDelta(t, it.cfg.Modifiers.FirstSeenScoreIncrease, res.FirstSeenScore, 0.001, "first seen score should equal the first seen score increase config value")
		require.EqualValues(t, expected.firstSeen.UTC(), res.FirstSeen, "first seen date should match")
		require.InDelta(t, it.cfg.Modifiers.MissingHostCountScoreIncrease, res.MissingHostHeaderScore, 0.001, "missing host header score should equal the missing host header increase score config value")
		require.InDelta(t, it.cfg.Modifiers.RareSignatureScoreIncrease, res.TotalModifierScore, 0.001, "total modifier score should equal the rare signature increase score config value")
		require.ElementsMatch(t, expected.portProtoService, res.PortProtoService, "port:proto:service arrays should match")
		i++
	}
	rows.Close()
	require.EqualValues(t, 1, i, "there should only be one row for an aggregated result in the mixtape: 73.54.23.243 -> 64.225.56.201")

	// verify modifier for the threat
	// there should only be the rare signature modifier (for the modifiers that are on their own row)
	rows, err = it.db.Conn.Query(ctx, `--sql
		SELECT modifier_name, modifier_value, modifier_score FROM threat_mixtape
		WHERE src = {src:String} AND dst = {dst:String}
		AND modifier_name != ''
		AND import_id = (SELECT argMax(import_id, analyzed_at) FROM threat_mixtape)
	`)
	require.NoError(t, err, "retrieving the modifiers for this threat should not error")

	i = 0
	for rows.Next() {
		var name, value string
		var score float32
		err = rows.Scan(&name, &value, &score)
		require.NoError(t, err)

		require.Equal(t, "rare_signature", name, "the modifier should be rare signature")
		require.Equal(t, "Modzilla/0.0001 (Atari 7800)", value, "the rare signature should be Modzilla/0.0001 (Atari 7800)")
		require.InDelta(t, it.cfg.Modifiers.RareSignatureScoreIncrease, score, 0.001, "the rare signature score should match the config modifier value")
		i++
	}
	require.EqualValues(t, 1, i, "there should only be one modifier for 73.54.23.243 -> 64.225.56.201")

	//  verify that the threat has the ICMP protocol in port:proto:service (in a previous import)
	ctx = it.db.QueryParameters(clickhouse.Parameters{
		// last seen is the hour that ICMP was seen
		"last_seen": fmt.Sprintf("%d", time.Unix(1713506400, 0).UTC().Unix()),
		"src":       expected.src,
		"dst":       expected.dst,
	})

	var portProto []string
	expectedProtoService := []string{"icmp:8/0", "80:tcp:http", "22:tcp:ssh"}
	err = it.db.Conn.QueryRow(ctx, `--sql
		SELECT flatten(groupArray(port_proto_service)) FROM threat_mixtape
		WHERE src = {src:String} AND dst = {dst:String} AND toStartOfHour(last_seen) = fromUnixTimestamp({last_seen:Int64})
	`).Scan(&portProto)
	require.NoError(t, err, "getting the single mixtape result shouldn't error")
	require.ElementsMatch(t, portProto, expectedProtoService, "old port:proto:service array containing icmp should match expected output")
}

// TestTmpTables makes sure that temp tables are getting truncated on each import, including hour imports, so that
// only the connections from the current import are in the tmp tables
func (it *MissingHostSuite) TestTmpTables() {
	t := it.T()

	cases := []struct {
		hash     string
		srcTable string
		tmpTable string
		col      string
		tld      string
	}{
		{srcTable: "conn", tmpTable: "uconn_tmp", hash: "2E20BF90DA74FC0ACEC1A75BED4B4A7C", col: "hash"},
		{srcTable: "ssl", tmpTable: "sniconn_tmp", hash: "B72C70EFE29E20962EC6A2AE74D57149", col: "hash"},
		{srcTable: "http", tmpTable: "sniconn_tmp", hash: "8CA65FDEB4184DEF86589A874F7D4997", col: "hash"},
		{srcTable: "dns", tmpTable: "dns_tmp", hash: "0F3D1D4F2CB470E666996F87208B5FDC", col: "tld", tld: "236.211.203.35.in-addr.arpa"},
	}

	for _, testCase := range cases {
		hash2 := testCase.hash
		if testCase.tld != "" {
			hash2 = testCase.tld
		}

		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"src_table": testCase.srcTable,
			"tmp_table": testCase.tmpTable,
			"hash":      testCase.hash,
			"col":       testCase.col,
			"hash2":     hash2,
		})
		var logCount, tmpCount uint64
		err := it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {src_table:Identifier} 
			WHERE hash = unhex({hash:String})
		`).Scan(&logCount)
		require.NoError(t, err)
		require.Positive(t, logCount, "there should a record in the %s table for a connection not used in the last hour, got: %d", testCase.srcTable, logCount)

		err = it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {tmp_table:Identifier}
			WHERE {col:Identifier} = unhex({hash2:String})
		`).Scan(&tmpCount)
		require.NoError(t, err)
		require.EqualValues(t, 0, tmpCount, "there should be no entries in the %s table for a connection only used in one hour, got: %d", testCase.tmpTable, tmpCount)
	}
}
