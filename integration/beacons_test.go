package integration_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/activecm/rita/v5/analysis"
	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// **** Beacon Integration Tests ****
// These tests verify the main beacon score and the four sub-scores for a handful of known beacons.
// They validate that the output of the beacon scoring functions are properly working together
// to produce the desired score.
func (it *ValidDatasetTestSuite) TestBeacons() { // used by valid dataset test suite

	it.Run("Beacon Type Counts", func() {
		t := it.T()
		// check the total count for each beacon type
		type countRes struct {
			BeaconType string `ch:"beacon_type"`
			Count      uint64 `ch:"count"`
		}

		cases := []countRes{
			{BeaconType: "sni", Count: 3383},
			{BeaconType: "ip", Count: 1252},
		}

		var res []countRes
		// check total beacon count by beacon type
		err := it.db.Conn.Select(it.db.GetContext(), &res, `
		SELECT beacon_type, count() as count FROM threat_mixtape
		WHERE beacon_score > 0
		GROUP BY beacon_type
		ORDER BY count DESC
	`)
		require.NoError(t, err)
		require.EqualValues(t, res, cases)
	})

	// verify known beacon scores
	it.Run("Verify Known Scores", func() {
		t := it.T()

		// these values can be validated by using ./get_beacon_info.py
		beaconCases := []struct {
			name          string
			mixtapeResult analysis.ThreatMixtape
		}{
			{
				name: "10.55.100.111 -> 165.227.216.194",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:        net.ParseIP("10.55.100.111"),
						SrcNUID:    util.UnknownPrivateNetworkUUID,
						Dst:        net.ParseIP("165.227.216.194"),
						DstNUID:    util.PublicNetworkUUID,
						Count:      20054,
						BeaconType: "ip",
					}, Beacon: analysis.Beacon{
						Score:          1,
						TimestampScore: 1,
						DataSizeScore:  1,
						DurationScore:  1,
						HistogramScore: 1,
					}},
			},
			{
				name: "10.55.100.111 -> tile-service.weather.microsoft.com",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:     net.ParseIP("10.55.100.111"),
						SrcNUID: util.UnknownPrivateNetworkUUID,
						FQDN:    "tile-service.weather.microsoft.com",
						DstNUID: util.PublicNetworkUUID,
						Count:   48,
					}, Beacon: analysis.Beacon{
						BeaconType:     "sni",
						Score:          1,
						TimestampScore: 1,
						DataSizeScore:  0.998,
						DurationScore:  1,
						HistogramScore: 1,
					}},
			},
			{
				name: "10.55.100.109 -> www.alexa.com",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:     net.ParseIP("10.55.100.109"),
						SrcNUID: util.UnknownPrivateNetworkUUID,
						FQDN:    "www.alexa.com",
						Count:   607,
					}, Beacon: analysis.Beacon{
						BeaconType:     "sni",
						Score:          0.896,
						TimestampScore: 0.999,
						DataSizeScore:  0.47,
						DurationScore:  1,
						HistogramScore: 0.937,
					}},
			},
			{
				name: "10.55.100.103 -> www.bankofamerica.com",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:     net.ParseIP("10.55.100.103"),
						SrcNUID: util.UnknownPrivateNetworkUUID,
						FQDN:    "www.bankofamerica.com",
						Count:   24,
					}, Beacon: analysis.Beacon{
						BeaconType:     "sni",
						Score:          0.465,
						TimestampScore: 0.407,
						DataSizeScore:  0.632,
						DurationScore:  0.823,
						HistogramScore: 0,
					}},
			},
		}

		for _, test := range beaconCases {
			t.Run(test.name, func(t *testing.T) {
				var hash util.FixedString
				var err error

				// set beacon value
				beacon := test.mixtapeResult

				// get the hash
				if beacon.FQDN != "" {
					hash, err = util.NewFixedStringHash(beacon.Src.String(), beacon.SrcNUID.String(), beacon.FQDN)
					require.NoError(t, err)
				} else {
					hash, err = util.NewFixedStringHash(beacon.Src.String(), beacon.SrcNUID.String(), beacon.Dst.String(), beacon.DstNUID.String())
					require.NoError(t, err)
				}

				// create a context with the hash parameter
				ctx := clickhouse.Context(it.db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
					"hash": hash.Hex(),
				}))
				var res analysis.ThreatMixtape
				err = it.db.Conn.QueryRow(ctx, `
							SELECT src, src_nuid, dst, dst_nuid, fqdn, sum(count) as count, toFloat32(sum(beacon_score)) as beacon_score, toFloat32(sum(ts_score)) as ts_score, toFloat32(sum(ds_score)) as ds_score, toFloat32(sum(dur_score)) as dur_score, toFloat32(sum(hist_score)) as hist_score FROM threat_mixtape
							WHERE hash = unhex({hash:String})
							GROUP BY src, src_nuid, dst, dst_nuid, fqdn
						`).ScanStruct(&res)
				require.NoError(t, err)
				require.EqualValues(t, beacon.Count, res.Count, "beacon connection count must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
				require.InDelta(t, beacon.Score, res.Score, 0.05, "beacon score must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
				require.InDelta(t, beacon.TimestampScore, res.TimestampScore, 0.05, "beacon timestamp score must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
				require.InDelta(t, beacon.DataSizeScore, res.DataSizeScore, 0.05, "beacon data size score must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
				require.InDelta(t, beacon.DurationScore, res.DurationScore, 0.05, "beacon duration score must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
				require.InDelta(t, beacon.HistogramScore, res.HistogramScore, 0.05, "beacon histogram score must match %s -> %s -> %s", beacon.Src.String(), beacon.Dst.String(), beacon.FQDN)
			})
		}
	})

	// verify that the strobe in this dataset is not reported as a beacon in the threat_mixtape table
	it.Run("Strobe Not Reported As Beacon", func() {
		t := it.T()
		var count uint64
		err := it.db.Conn.QueryRow(it.db.GetContext(), `
				SELECT sum(count) FROM threat_mixtape
				WHERE src = '192.168.88.2' AND dst = '165.227.88.15'
				AND beacon_score > 0
			`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "known strobe 192.168.88.2 -> 165.227.88.15 should not exist in beacons")
	})

	// verify that there are no beacons with a connection count lower than the connection threshold
	it.Run("Beacons Follow Connection Threshold", func() {
		t := it.T()
		var count uint64

		ctx := clickhouse.Context(it.db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
			"threshold": strconv.Itoa(int(it.cfg.Scoring.Beacon.UniqueConnectionThreshold)),
		}))
		err := it.db.Conn.QueryRow(ctx, `
					SELECT count() FROM threat_mixtape
					WHERE beacon_score > 0 AND ts_unique < {threshold:Int}
				`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "there should be no beacons with a unique timestamp count that is less than or equal to the connection threshold")

	})

}

// Verify proxy beacons
func TestProxyBeacons(t *testing.T) {
	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err, "loading config should not return an error")

	cfg.DBConnection = dockerInfo.clickhouseConnection
	err = config.UpdateConfig(cfg)
	require.NoError(t, err, "updating config should not return an error")

	// import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/proxy", "test_proxy_beacons", false, false)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "test_proxy_beacons", cfg, nil)
	require.NoError(t, err)

	// check the total count for each beacon type
	t.Run("Proxy Beacon Count", func(t *testing.T) {
		var countRes uint64

		// check total beacon count by beacon type
		err = db.Conn.QueryRow(db.GetContext(), `
				SELECT count(DISTINCT hash) as count FROM threat_mixtape
				HAVING sum(proxy_count) > 0 AND sum(beacon_score) > 0
			`).Scan(&countRes)
		require.NoError(t, err)

		require.EqualValues(t, 2, countRes, "there should be two beacons with proxy connections")
	})

	// verify known beacon scores
	t.Run("Verify Known Scores", func(t *testing.T) {

		// These values can be validated by using ./get_beacon_info.py
		beaconCases := []struct {
			name          string
			mixtapeResult analysis.ThreatMixtape
		}{
			{
				name: "10.136.0.18 -> www.honestimnotevil.com",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:              net.ParseIP("10.136.0.18"),
						SrcNUID:          util.UnknownPrivateNetworkUUID,
						FQDN:             "www.honestimnotevil.com",
						Count:            357,
						ProxyCount:       357,
						TotalBytes:       963595,
						TotalDuration:    12.454628000000003,
						PortProtoService: []string{"3128:tcp:http,ssl"},
					}, Beacon: analysis.Beacon{
						BeaconType:     "sni",
						Score:          0.979,
						TimestampScore: 0.921,
						DataSizeScore:  0.995,
						DurationScore:  1,
						HistogramScore: 1,
					}},
			},
			{
				name: "10.136.0.18 -> www.google.com",
				mixtapeResult: analysis.ThreatMixtape{
					AnalysisResult: analysis.AnalysisResult{
						Src:              net.ParseIP("10.136.0.18"),
						SrcNUID:          util.UnknownPrivateNetworkUUID,
						FQDN:             "www.google.com",
						Count:            6,
						ProxyCount:       6,
						TotalBytes:       139385,
						TotalDuration:    0.725752,
						PortProtoService: []string{"3128:tcp:http,ssl"},
					}, Beacon: analysis.Beacon{
						BeaconType:     "sni",
						Score:          0.586,
						TimestampScore: 0.48,
						DataSizeScore:  0.865,
						DurationScore:  1,
						HistogramScore: 0,
					}},
			},
		}

		for _, test := range beaconCases {
			t.Run(test.name, func(t *testing.T) {
				// set beacon value
				beacon := test.mixtapeResult

				// get the hash
				hash, err := util.NewFixedStringHash(beacon.Src.String(), beacon.SrcNUID.String(), beacon.FQDN)
				require.NoError(t, err)

				// create a context with the hash parameter
				ctx := clickhouse.Context(db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
					"hash": hash.Hex(),
				}))

				var res analysis.ThreatMixtape
				err = db.Conn.QueryRow(ctx, `
						SELECT src, src_nuid, dst, dst_nuid, fqdn, count, proxy_count, beacon_score, ts_score, ds_score, dur_score, hist_score FROM threat_mixtape
						WHERE hash = unhex({hash:String}) AND count > 0
					`).ScanStruct(&res)
				require.NoError(t, err)

				// verfiy basic proxy beacon requirements
				require.Greater(t, res.ProxyCount, uint64(0), "proxy count must be greater than 0")
				require.GreaterOrEqual(t, int64(res.Count), cfg.Scoring.Beacon.UniqueConnectionThreshold, "connection count must be greater than or equal to the connection threshold")

				// verify scores
				require.EqualValues(t, beacon.Count, res.AnalysisResult.Count, "connection count must match expected value")
				require.EqualValues(t, beacon.ProxyCount, res.ProxyCount, "proxy count must match expected value")
				require.InDelta(t, beacon.Score, res.Score, 0.05, "beacon score must match expected value")
				require.InDelta(t, beacon.TimestampScore, res.TimestampScore, 0.05, "timestamp score must match expected value")
				require.InDelta(t, beacon.DataSizeScore, res.DataSizeScore, 0.05, "data size score must match expected value")
				require.InDelta(t, beacon.DurationScore, res.DurationScore, 0.05, "duration score must match expected value")
				require.InDelta(t, beacon.HistogramScore, res.HistogramScore, 0.05, "histogram score must match expected value")

			})
		}

	})

}
