package integration_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/activecm/rita/v5/importer"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
)

// testExplodedDNS tests the exploded_dns table fields and values
func (it *ValidDatasetTestSuite) TestExplodedDNS() {

	var countResult struct {
		Count uint64 `ch:"count"`
	}

	// test exploded_dns and pdns values for some fqdns
	tests := []struct {
		name        string
		fqdn        string
		subdomains  uint64
		visits      uint64
		resolvedIPs uint64
	}{
		{
			name:        "Root Domain",
			fqdn:        "microsoft.com",
			subdomains:  67,
			visits:      1687,
			resolvedIPs: 29,
		},
		{
			name:        "Subdomain",
			fqdn:        "dnsc.r-1x.com",
			subdomains:  62466,
			visits:      108911,
			resolvedIPs: 0,
		},
		{
			name:        "C2 Over DNS",
			fqdn:        "r-1x.com",
			subdomains:  62468,
			visits:      109227,
			resolvedIPs: 1,
		},
	}

	for _, test := range tests {
		it.Run(test.name, func() {
			t := it.T()

			ctx := clickhouse.Context(it.db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
				"fqdn": test.fqdn,
			}))

			var result struct {
				Subdomains uint64 `ch:"subdomains"`
				Visits     uint64 `ch:"visits"`
			}

			err := it.db.Conn.QueryRow(ctx, `
				SELECT uniqExactMerge(subdomains) as subdomains, countMerge(visits) as visits FROM exploded_dns
				WHERE fqdn = {fqdn:String}
			`).ScanStruct(&result)
			require.NoError(t, err, "querying exploded_dns table should not produce an error")
			require.Equal(t, test.subdomains, result.Subdomains, "exploded_dns subdomain count should match expected value")
			require.Equal(t, test.visits, result.Visits, "exploded_dns visit count should match expected value")

			err = it.db.Conn.QueryRow(ctx, `
				SELECT countIf(endsWith(query, concat('.', {fqdn:String})) OR query = {fqdn:String}) as count FROM dns
			`).ScanStruct(&countResult)
			require.NoError(t, err, "querying dns table should not produce an error")
			require.EqualValues(t, test.visits, countResult.Count, "dns visit count should match expected value")

			err = it.db.Conn.QueryRow(ctx, `
				SELECT count(DISTINCT resolved_ip) as count FROM pdns
				WHERE endsWith(fqdn, {fqdn:String})
			`).ScanStruct(&countResult)
			require.NoError(t, err, "querying pdns table should not produce an error")
			require.EqualValues(t, test.resolvedIPs, countResult.Count, "pdns resolved_ips count should match expected value")

		})
	}

	// ensure that there are no fqdns that are empty strings, only dots, or don't contain a dot
	it.Run("No FQDNS Empty", func() {
		t := it.T()
		err := it.db.Conn.QueryRow(it.db.GetContext(), `
			SELECT count() as count FROM exploded_dns
			WHERE fqdn = '' OR fqdn = ' ' OR fqdn = '.' OR position('.' IN fqdn) == 0
		`).ScanStruct(&countResult)
		require.NoError(t, err, "querying exploded_dns table should not produce an error")
		require.EqualValues(t, 0, countResult.Count, "fqdn fields in exploded_dns table must not be malformed")
	})

	// ensure that PDNS has the correct counts
	it.Run("PDNS_Raw Counts", func() {
		t := it.T()
		err := it.db.Conn.QueryRow(it.db.GetContext(), `
			SELECT count() as count FROM pdns_raw
		`).ScanStruct(&countResult)
		require.NoError(t, err, "querying pdns_raw table should not produce an error")
		require.EqualValues(t, 208296, countResult.Count, "pdns_raw count should match expected value")
	})

}

// testUConn tests the uconn table fields, values and hourly counts
func (it *ValidDatasetTestSuite) TestUconn() {

	type hourlyCount struct {
		Count uint64 `ch:"count"`
		Hour  uint32 `ch:"hour_timestamp"`
	}

	// test counts per hour for a unique connection pair
	tests := []struct {
		src               string
		dst               string
		localSrc          bool
		localDst          bool
		count             int64
		totalSrcBytes     int64
		totalDstBytes     int64
		totalSrcIPBytes   int
		totalDstIPBytes   int
		totalIPBytes      int
		totalSrcPackets   int
		totalDstPackets   int
		totalDuration     float64
		tsListLen         int
		srcIPBytesListLen int
		firstSeen         int
		lastSeen          int
		hourlyCounts      []hourlyCount
	}{
		{
			src: "192.168.88.2", dst: "165.227.88.15",
			localSrc:          true,
			localDst:          false,
			count:             108858,
			totalSrcBytes:     6723739,
			totalDstBytes:     8900291,
			totalSrcIPBytes:   9780272,
			totalDstIPBytes:   11945399,
			totalIPBytes:      21725671,
			totalSrcPackets:   108870,
			totalDstPackets:   108753,
			totalDuration:     7588.427,
			firstSeen:         1517336042, // 1517336042.279652
			lastSeen:          1517422440, // 1517422440.290417
			tsListLen:         86400,      // we max out tslist at 86400, actual number of unique ts is 108856
			srcIPBytesListLen: 86400,      // we max out tslist at 86400, actual number of unique ts is 108858
			hourlyCounts: []hourlyCount{
				{Count: 1568, Hour: 1517335200},
				{Count: 6255, Hour: 1517338800},
				{Count: 5783, Hour: 1517342400},
				{Count: 5126, Hour: 1517346000},
				{Count: 4735, Hour: 1517349600},
				{Count: 4512, Hour: 1517353200},
				{Count: 4407, Hour: 1517356800},
				{Count: 4415, Hour: 1517360400},
				{Count: 4399, Hour: 1517364000},
				{Count: 4470, Hour: 1517367600},
				{Count: 4481, Hour: 1517371200},
				{Count: 4464, Hour: 1517374800},
				{Count: 4438, Hour: 1517378400},
				{Count: 4452, Hour: 1517382000},
				{Count: 4481, Hour: 1517385600},
				{Count: 4377, Hour: 1517389200},
				{Count: 4510, Hour: 1517392800},
				{Count: 4451, Hour: 1517396400},
				{Count: 4394, Hour: 1517400000},
				{Count: 4415, Hour: 1517403600},
				{Count: 4346, Hour: 1517407200},
				{Count: 4412, Hour: 1517410800},
				{Count: 4432, Hour: 1517414400},
				{Count: 4494, Hour: 1517418000},
				{Count: 1041, Hour: 1517421600},
			},
		},
		{
			src: "10.55.100.111", dst: "165.227.216.194",
			localSrc:          true,
			localDst:          false,
			count:             20054,
			totalSrcBytes:     0,
			totalDstBytes:     0,
			totalSrcIPBytes:   1042860,
			totalDstIPBytes:   802160,
			totalIPBytes:      1845020,
			totalSrcPackets:   20055,
			totalDstPackets:   20054,
			totalDuration:     1292.3005,
			firstSeen:         1517336052, // 1517336052.713711
			lastSeen:          1517422432, // 1517422432.999706
			tsListLen:         20054,
			srcIPBytesListLen: 20054,
			hourlyCounts: []hourlyCount{
				{Count: 642, Hour: 1517335200},
				{Count: 837, Hour: 1517338800},
				{Count: 836, Hour: 1517342400},
				{Count: 831, Hour: 1517346000},
				{Count: 825, Hour: 1517349600},
				{Count: 837, Hour: 1517353200},
				{Count: 852, Hour: 1517356800},
				{Count: 828, Hour: 1517360400},
				{Count: 831, Hour: 1517364000},
				{Count: 834, Hour: 1517367600},
				{Count: 831, Hour: 1517371200},
				{Count: 843, Hour: 1517374800},
				{Count: 843, Hour: 1517378400},
				{Count: 837, Hour: 1517382000},
				{Count: 837, Hour: 1517385600},
				{Count: 828, Hour: 1517389200},
				{Count: 840, Hour: 1517392800},
				{Count: 831, Hour: 1517396400},
				{Count: 834, Hour: 1517400000},
				{Count: 838, Hour: 1517403600},
				{Count: 833, Hour: 1517407200},
				{Count: 828, Hour: 1517410800},
				{Count: 843, Hour: 1517414400},
				{Count: 834, Hour: 1517418000},
				{Count: 201, Hour: 1517421600},
			},
		},
		{
			src: "10.55.200.10", dst: "216.239.34.10",
			localSrc:          true,
			localDst:          false,
			count:             3856,
			totalSrcBytes:     181438,
			totalDstBytes:     280134,
			totalSrcIPBytes:   289630,
			totalDstIPBytes:   388326,
			totalIPBytes:      677956,
			totalSrcPackets:   3864,
			totalDstPackets:   3864,
			totalDuration:     337.444094,
			firstSeen:         1517336164, // 1517336164.364496
			lastSeen:          1517414232, // 1517414232.320150
			tsListLen:         3856,
			srcIPBytesListLen: 3856,
			hourlyCounts: []hourlyCount{
				{Count: 120, Hour: 1517335200},
				{Count: 187, Hour: 1517338800},
				{Count: 174, Hour: 1517342400},
				{Count: 164, Hour: 1517346000},
				{Count: 175, Hour: 1517349600},
				{Count: 177, Hour: 1517353200},
				{Count: 174, Hour: 1517356800},
				{Count: 187, Hour: 1517360400},
				{Count: 186, Hour: 1517364000},
				{Count: 164, Hour: 1517367600},
				{Count: 164, Hour: 1517371200},
				{Count: 166, Hour: 1517374800},
				{Count: 201, Hour: 1517378400},
				{Count: 197, Hour: 1517382000},
				{Count: 179, Hour: 1517385600},
				{Count: 188, Hour: 1517389200},
				{Count: 174, Hour: 1517392800},
				{Count: 195, Hour: 1517396400},
				{Count: 169, Hour: 1517400000},
				{Count: 178, Hour: 1517403600},
				{Count: 170, Hour: 1517407200},
				{Count: 167, Hour: 1517410800},
			},
		},
	}

	for _, test := range tests {
		it.Run(test.src+"-"+test.dst, func() {
			t := it.T()
			ctx := clickhouse.Context(it.db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
				"src": test.src,
				"dst": test.dst,
			}))

			t.Run("Values", func(t *testing.T) {
				type res struct {
					importer.ConnEntry
					LocalSrc     bool   `ch:"src_local"`
					LocalDst     bool   `ch:"dst_local"`
					TotalIPBytes int64  `ch:"total_ip_bytes"`
					TSListLen    uint64 `ch:"ts_list_len"`
					BytesListLen uint64 `ch:"bytes_list_len"`
					Count        uint64 `ch:"count"`
					FirstSeen    uint32 `ch:"first_seen"`
					LastSeen     uint32 `ch:"last_seen"`
				}
				var result res
				// conn count
				err := it.db.Conn.QueryRow(ctx, `
				SELECT src, dst, src_local, dst_local,
					   countMerge(count) as count,
					   sumMerge(total_src_bytes) as src_bytes,
					   sumMerge(total_dst_bytes) as dst_bytes,
					   sumMerge(total_src_ip_bytes) as src_ip_bytes,
					   sumMerge(total_dst_ip_bytes) as dst_ip_bytes,
					   sumMerge(total_ip_bytes) as total_ip_bytes,
					   sumMerge(total_src_packets) as src_packets,
					   sumMerge(total_dst_packets) as dst_packets,
					   sumMerge(total_duration) as duration,
					   length(groupArrayMerge(86400)(ts_list)) as ts_list_len,
					   length(groupArrayMerge(86400)(src_ip_bytes_list)) as bytes_list_len,
					   toUnixTimestamp(minMerge(first_seen)) as first_seen,
					   toUnixTimestamp(maxMerge(last_seen)) as last_seen
					   FROM uconn
				WHERE src=={src:String} AND dst=={dst:String} 
				GROUP BY src, dst, src_local, dst_local
			`).ScanStruct(&result)
				require.NoError(t, err, "querying uconn table should not produce an error")

				require.EqualValues(t, test.count, result.Count, "count should match expected value")
				require.EqualValues(t, test.localSrc, result.LocalSrc, "src_local should match expected value")
				require.EqualValues(t, test.localDst, result.LocalDst, "dst_local should match expected value")
				require.EqualValues(t, test.totalSrcBytes, result.SrcBytes, "total_src_bytes should match expected value")
				require.EqualValues(t, test.totalDstBytes, result.DstBytes, "total_dst_bytes should match expected value")
				require.EqualValues(t, test.totalSrcIPBytes, result.SrcIPBytes, "total_src_ip_bytes should match expected value")
				require.EqualValues(t, test.totalDstIPBytes, result.DstIPBytes, "total_dst_ip_bytes should match expected value")
				require.EqualValues(t, test.totalIPBytes, result.TotalIPBytes, "total_ip_bytes should match expected value")
				require.EqualValues(t, test.totalSrcPackets, result.SrcPackets, "total_src_packets should match expected value")
				require.EqualValues(t, test.totalDstPackets, result.DstPackets, "total_dst_packets should match expected value")
				require.InDelta(t, test.totalDuration, result.Duration, 0.01, "total_duration should match expected value")
				require.EqualValues(t, test.tsListLen, result.TSListLen, "length of ts_list should match expected value")
				require.EqualValues(t, test.srcIPBytesListLen, result.BytesListLen, "length of src_ip_bytes_list should match expected value")
				require.EqualValues(t, test.firstSeen, result.FirstSeen, "first_seen should match expected value")
				require.EqualValues(t, test.lastSeen, result.LastSeen, "last_seen should match expected value")
			})

			t.Run("Hourly Counts", func(t *testing.T) {
				var res []hourlyCount

				// select each hour for this connection pair and count its connections (per hour)
				err := it.db.Conn.Select(ctx, &res, `
					SELECT toUnixTimestamp(hour) AS hour_timestamp, countMerge(count) AS count FROM uconn
					WHERE src=={src:String} AND dst=={dst:String}
					GROUP BY hour
					ORDER BY hour_timestamp
				`)
				require.NoError(t, err, "querying uconn should not produce an error")

				// ensure that the number of hourly counts matches the expected number
				require.EqualValues(t, len(test.hourlyCounts), len(res), "number of hourly count records must match expected value")

				// ensure that hourly counts match expected values
				require.Equal(t, test.hourlyCounts, res, "hourly counts must match expected values")
			})
		})
	}

}

// testUSNI tests the usni table fields, values and hourly counts
func (it *ValidDatasetTestSuite) TestUSNI() {
	type hourlyCount struct {
		Count uint64 `ch:"count"`
		Hour  uint32 `ch:"hour_timestamp"`
	}

	type test struct {
		src               string
		fqdn              string
		localSrc          bool
		localDst          bool
		count             int
		httpCount         int
		sslCount          int
		totalSrcBytes     int
		totalDstBytes     int
		totalSrcIPBytes   int
		totalDstIPBytes   int
		totalIPBytes      int
		totalSrcPackets   int
		totalDstPackets   int
		totalDuration     float64
		firstSeen         int
		lastSeen          int
		tsListLen         int
		uniqueTSListLen   int
		srcIPBytesListLen int
		serverIPs         []string
		proxyIPs          []string
		proxyCount        int
		hourlyCounts      []hourlyCount
	}

	testCases := []test{
		{
			src: "10.55.100.109", fqdn: "www.alexa.com",
			localSrc:          true,
			localDst:          false,
			count:             607,
			httpCount:         290,
			sslCount:          317,
			totalSrcIPBytes:   700378,      // 127890 + 572488 = 700378
			totalDstIPBytes:   23374587,    // 180570 + 23194017 = 23374587
			totalIPBytes:      24074965,    // 308460 + 23766505 = 24074965
			totalSrcBytes:     375130,      // 54810 + 320320 = 375130
			totalDstBytes:     23018743,    // 116290 + 22902453 = 23018743
			totalSrcPackets:   7944,        // 1740 + 6204 = 7944
			totalDstPackets:   8714,        // 1520 + 7194 = 8714
			totalDuration:     59949.50388, // 29042.726421 + 30906.777459 = 59949.50388
			tsListLen:         607,         // 290 + 317 = 607
			uniqueTSListLen:   354,
			srcIPBytesListLen: 607,
			firstSeen:         1517336154, // http: 1517336154.078555 ssl: 1517336154.222757
			lastSeen:          1517422323, // http: 1517422323.066450 ssl: 1517422323.202331
			serverIPs:         []string{"52.55.1.124", "34.196.128.45", "52.44.164.170", "34.198.172.204"},
			proxyIPs:          []string{},
			proxyCount:        0,
			hourlyCounts: []hourlyCount{
				{Count: 18, Hour: 1517335200},
				{Count: 24, Hour: 1517338800},
				{Count: 27, Hour: 1517342400},
				{Count: 28, Hour: 1517346000},
				{Count: 24, Hour: 1517349600},
				{Count: 26, Hour: 1517353200},
				{Count: 26, Hour: 1517356800},
				{Count: 24, Hour: 1517360400},
				{Count: 26, Hour: 1517364000},
				{Count: 26, Hour: 1517367600},
				{Count: 24, Hour: 1517371200},
				{Count: 24, Hour: 1517374800},
				{Count: 24, Hour: 1517378400},
				{Count: 24, Hour: 1517382000},
				{Count: 28, Hour: 1517385600},
				{Count: 24, Hour: 1517389200},
				{Count: 26, Hour: 1517392800},
				{Count: 24, Hour: 1517396400},
				{Count: 26, Hour: 1517400000},
				{Count: 24, Hour: 1517403600},
				{Count: 24, Hour: 1517407200},
				{Count: 28, Hour: 1517410800},
				{Count: 24, Hour: 1517414400},
				{Count: 28, Hour: 1517418000},
				{Count: 6, Hour: 1517421600},
			},
		},
		{
			src: "10.55.100.108", fqdn: "pixel.adsafeprotected.com",
			localSrc:          true,
			localDst:          false,
			count:             163, // 132 + 31 = 163
			httpCount:         132,
			sslCount:          31,
			totalSrcBytes:     105463,     // 69233 + 36230 = 105463
			totalDstBytes:     626545,     // 129423 + 497122 = 626545
			totalSrcIPBytes:   151619,     // 98537 + 53082 = 151619
			totalDstIPBytes:   669573,     // 158087 + 511486 = 669573
			totalIPBytes:      821192,     // 256624 + 564568 = 821192
			totalSrcPackets:   1105,       // 693 + 412 = 1105
			totalDstPackets:   1027,       // 677 + 350 = 1027
			totalDuration:     917.166567, // 390.535353 + 526.631214 = 917.166567
			tsListLen:         163,        // 132 + 31 = 163
			uniqueTSListLen:   78,
			srcIPBytesListLen: 163,
			firstSeen:         1517344325, // http: 1517344325.773730 ssl: 1517344330.582307
			lastSeen:          1517420230, // http: 1517420229.724142 ssl: 1517420230.547946
			serverIPs:         []string{"69.172.216.55"},
			proxyIPs:          []string{},
			proxyCount:        0,
			hourlyCounts: []hourlyCount{
				{Count: 20, Hour: 1517342400},
				{Count: 10, Hour: 1517346000},
				{Count: 8, Hour: 1517349600},
				{Count: 15, Hour: 1517356800},
				{Count: 11, Hour: 1517364000},
				{Count: 10, Hour: 1517371200},
				{Count: 10, Hour: 1517374800},
				{Count: 13, Hour: 1517378400},
				{Count: 3, Hour: 1517382000},
				{Count: 16, Hour: 1517385600},
				{Count: 10, Hour: 1517389200},
				{Count: 1, Hour: 1517396400},
				{Count: 10, Hour: 1517400000},
				{Count: 8, Hour: 1517410800},
				{Count: 8, Hour: 1517414400},
				{Count: 10, Hour: 1517418000},
			},
		},
		{
			src: "10.55.100.105", fqdn: "tile-service.weather.microsoft.com",
			localSrc:          true,
			localDst:          false,
			count:             48,
			httpCount:         48,
			sslCount:          0,
			totalSrcBytes:     10224,
			totalDstBytes:     221820,
			totalSrcIPBytes:   24012,
			totalDstIPBytes:   234248,
			totalIPBytes:      258260,
			totalSrcPackets:   324,
			totalDstPackets:   290,
			totalDuration:     1533.756826, // 1533.756826
			tsListLen:         48,
			uniqueTSListLen:   48,
			srcIPBytesListLen: 48,
			firstSeen:         1517336820, // http: 1517336820.525381 ssl: -
			lastSeen:          1517421421, // http: 1517421421.571744 ssl: -
			serverIPs:         []string{"23.52.161.212", "23.63.158.27", "23.4.4.31", "23.222.23.103", "23.63.179.115", "23.79.207.65"},
			proxyIPs:          []string{},
			proxyCount:        0,
			hourlyCounts: []hourlyCount{
				{Count: 2, Hour: 1517335200},
				{Count: 2, Hour: 1517338800},
				{Count: 2, Hour: 1517342400},
				{Count: 2, Hour: 1517346000},
				{Count: 2, Hour: 1517349600},
				{Count: 2, Hour: 1517353200},
				{Count: 2, Hour: 1517356800},
				{Count: 2, Hour: 1517360400},
				{Count: 2, Hour: 1517364000},
				{Count: 2, Hour: 1517367600},
				{Count: 2, Hour: 1517371200},
				{Count: 2, Hour: 1517374800},
				{Count: 2, Hour: 1517378400},
				{Count: 2, Hour: 1517382000},
				{Count: 2, Hour: 1517385600},
				{Count: 2, Hour: 1517389200},
				{Count: 2, Hour: 1517392800},
				{Count: 2, Hour: 1517396400},
				{Count: 2, Hour: 1517400000},
				{Count: 2, Hour: 1517403600},
				{Count: 2, Hour: 1517407200},
				{Count: 2, Hour: 1517410800},
				{Count: 2, Hour: 1517414400},
				{Count: 2, Hour: 1517418000},
			},
		},
		{
			src:               "10.55.100.104",
			fqdn:              "www.facebook.com",
			localSrc:          true,
			localDst:          false,
			count:             183,
			httpCount:         0,
			sslCount:          183,
			totalSrcIPBytes:   259611,
			totalDstIPBytes:   836534,
			totalIPBytes:      1096145,
			totalSrcBytes:     152215,
			totalDstBytes:     726418,
			totalSrcPackets:   2630,
			totalDstPackets:   2698,
			totalDuration:     12005.465565,
			tsListLen:         183,
			uniqueTSListLen:   119,
			srcIPBytesListLen: 183,
			firstSeen:         1517336527, // 1517336527.546436
			lastSeen:          1517422327, // 1517422327.673738
			serverIPs:         []string{"157.240.2.35"},
			proxyIPs:          []string{},
			proxyCount:        0,
			hourlyCounts: []hourlyCount{
				{Count: 5, Hour: 1517335200},
				{Count: 12, Hour: 1517338800},
				{Count: 9, Hour: 1517342400},
				{Count: 4, Hour: 1517346000},
				{Count: 10, Hour: 1517349600},
				{Count: 11, Hour: 1517353200},
				{Count: 16, Hour: 1517356800},
				{Count: 3, Hour: 1517360400},
				{Count: 9, Hour: 1517364000},
				{Count: 3, Hour: 1517367600},
				{Count: 5, Hour: 1517371200},
				{Count: 10, Hour: 1517374800},
				{Count: 8, Hour: 1517378400},
				{Count: 7, Hour: 1517382000},
				{Count: 6, Hour: 1517385600},
				{Count: 5, Hour: 1517389200},
				{Count: 9, Hour: 1517392800},
				{Count: 9, Hour: 1517396400},
				{Count: 5, Hour: 1517400000},
				{Count: 9, Hour: 1517403600},
				{Count: 4, Hour: 1517407200},
				{Count: 9, Hour: 1517410800},
				{Count: 8, Hour: 1517414400},
				{Count: 3, Hour: 1517418000},
				{Count: 4, Hour: 1517421600},
			},
		},
	}

	var result struct {
		Count             uint64   `ch:"count"`
		LocalSrc          bool     `ch:"src_local"`
		LocalDst          bool     `ch:"dst_local"`
		TotalSrcIPBytes   int64    `ch:"total_src_ip_bytes"`
		TotalDstIPBytes   int64    `ch:"total_dst_ip_bytes"`
		TotalIPBytes      int64    `ch:"total_ip_bytes"`
		TotalSrcBytes     int64    `ch:"total_src_bytes"`
		TotalDstBytes     int64    `ch:"total_dst_bytes"`
		TotalSrcPackets   int64    `ch:"total_src_packets"`
		TotalDstPackets   int64    `ch:"total_dst_packets"`
		TotalDuration     float64  `ch:"total_duration"`
		TSListLen         uint64   `ch:"ts_list_len"`
		UniqueTSListLen   uint64   `ch:"unique_ts_list_len"`
		UniqueTSCount     uint64   `ch:"unique_ts_count"`
		SrcIPBytesListLen uint64   `ch:"src_ip_bytes_list_len"`
		FirstSeen         uint32   `ch:"first_seen"`
		LastSeen          uint32   `ch:"last_seen"`
		ServerIPs         []string `ch:"server_ips"`
		ProxyIPs          []string `ch:"proxy_ips"`
		ProxyCount        uint64   `ch:"proxy_count"`
		ProxyBoolCount    uint64   `ch:"proxy_bool_count"`
	}

	for i := range testCases {
		test := testCases[i]
		it.Run(test.src+"-"+test.fqdn, func() {
			t := it.T()

			ctx := clickhouse.Context(it.db.GetContext(), clickhouse.WithParameters(clickhouse.Parameters{
				"src":  test.src,
				"fqdn": test.fqdn,
			}))

			t.Run("Values", func(t *testing.T) {
				err := it.db.Conn.QueryRow(ctx, `
			SELECT 
				src_local, dst_local,
				countMerge(count) as count,
				sumMerge(total_src_ip_bytes) as total_src_ip_bytes,
				sumMerge(total_dst_ip_bytes) as total_dst_ip_bytes,
				sumMerge(total_ip_bytes) as total_ip_bytes,
				sumMerge(total_src_bytes) as total_src_bytes,
				sumMerge(total_dst_bytes) as total_dst_bytes,
				sumMerge(total_src_packets) as total_src_packets,
				sumMerge(total_dst_packets) as total_dst_packets,
				sumMerge(total_duration) as total_duration,
				length(groupArrayMerge(86400)(ts_list)) as ts_list_len,
				length(arrayDistinct(groupArrayMerge(86400)(ts_list))) as unique_ts_list_len,
				uniqExactMerge(unique_ts_count) as unique_ts_count,
				length(groupArrayMerge(86400)(src_ip_bytes_list)) as src_ip_bytes_list_len,
				toUnixTimestamp(minMerge(first_seen)) as first_seen,
				toUnixTimestamp(maxMerge(last_seen)) as last_seen,
				groupUniqArrayMerge(10)(server_ips) as server_ips,
				groupUniqArrayMerge(10)(proxy_ips) as proxy_ips,
				countMerge(proxy_count) as proxy_count,
				countIf(proxy) as proxy_bool_count
			FROM usni
			WHERE src={src:String} AND fqdn={fqdn:String}
			GROUP BY src, fqdn, src_local, dst_local
		`).ScanStruct(&result)
				require.NoError(t, err)

				require.EqualValues(t, test.count, int(result.Count), "conn count should match expected value")
				require.EqualValues(t, test.totalSrcIPBytes, result.TotalSrcIPBytes, "total_src_ip_bytes should match expected value")
				require.EqualValues(t, test.totalDstIPBytes, int(result.TotalDstIPBytes), "total_dst_ip_bytes should match expected value")
				require.EqualValues(t, test.totalIPBytes, result.TotalIPBytes, "total_ip_bytes should match expected value")
				require.EqualValues(t, test.totalSrcBytes, result.TotalSrcBytes, "total_src_bytes should match expected value")
				require.EqualValues(t, test.totalDstBytes, result.TotalDstBytes, "total_dst_bytes should match expected value")
				require.EqualValues(t, test.totalSrcPackets, result.TotalSrcPackets, "total_src_packets should match expected value")
				require.EqualValues(t, test.totalDstPackets, result.TotalDstPackets, "total_dst_packets should match expected value")
				require.InDelta(t, test.totalDuration, result.TotalDuration, 0.1, "total_duration should match expected value")
				require.EqualValues(t, test.tsListLen, int(result.TSListLen), "number of elements in ts_list field should match expected value")
				require.EqualValues(t, test.uniqueTSListLen, int(result.UniqueTSListLen), "number of unique elements in ts_list field should match expected value")
				require.EqualValues(t, test.uniqueTSListLen, int(result.UniqueTSCount), "unique_ts_count should match expected value")
				require.EqualValues(t, test.srcIPBytesListLen, result.SrcIPBytesListLen, "number of elements in src_ip_bytes_list field should match expected value")
				require.EqualValues(t, test.firstSeen, result.FirstSeen, "first_seen should match expected value")
				require.EqualValues(t, test.lastSeen, result.LastSeen, "last_seen should match expected value")
				require.ElementsMatch(t, test.serverIPs, result.ServerIPs, "server_ips should match expected value")
				require.ElementsMatch(t, test.proxyIPs, result.ProxyIPs, "proxy_ips should match expected value")
				require.EqualValues(t, test.proxyCount, result.ProxyCount, "proxy_count should match expected value")
				require.EqualValues(t, test.proxyCount, result.ProxyBoolCount, "proxy field boolean count should match proxy_count")

				// separate queries for httpCount and sslCount
				var resCount uint64
				err = it.db.Conn.QueryRow(ctx, `
					SELECT countMerge(count) FROM usni 
					WHERE src={src:String} AND fqdn={fqdn:String} AND http=true 
					GROUP BY src, fqdn
				`).Scan(&resCount)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					require.NoError(t, err)
				}
				if errors.Is(err, sql.ErrNoRows) {
					resCount = 0
				}
				require.EqualValues(t, test.httpCount, int(resCount), "http conn count should match expected value")

				err = it.db.Conn.QueryRow(ctx, `
					SELECT countMerge(count) as ssl_count FROM usni 
					WHERE src={src:String} AND fqdn={fqdn:String} AND http=false 
					GROUP BY src, fqdn
				`).Scan(&resCount)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					require.NoError(t, err)
				}
				if errors.Is(err, sql.ErrNoRows) {
					resCount = 0
				}
				require.EqualValues(t, test.sslCount, int(resCount), "ssl conn count should match expected value")

			})

			t.Run("Hourly Counts", func(t *testing.T) {
				var res []hourlyCount

				// select each hour for this connection pair and count its connections (per hour)
				err := it.db.Conn.Select(ctx, &res, `
					SELECT toUnixTimestamp(hour) AS hour_timestamp, countMerge(count) AS count FROM usni
					WHERE src=={src:String} AND fqdn=={fqdn:String}
					GROUP BY hour
					ORDER BY hour_timestamp
				`)
				require.NoError(t, err, "querying usni should not produce an error")

				// ensure that the number of hourly counts matches the expected number
				require.EqualValues(t, len(test.hourlyCounts), len(res), "number of hourly count records must match expected value")

				// ensure that hourly counts match expected values
				require.Equal(t, test.hourlyCounts, res, "hourly counts must match expected values")
			})
		})
	}
}

func (it *ValidDatasetTestSuite) TestLongConnections() {
	t := it.T()

	type testCase struct {
		src           string
		dst           string
		totalDuration float64
	}

	topThree := []testCase{
		{
			src:           "::ffff:10.55.100.100",
			dst:           "::ffff:65.52.108.225",
			totalDuration: 86222.3655,
		},
		{
			src:           "::ffff:10.55.100.107",
			dst:           "::ffff:111.221.29.113",
			totalDuration: 86220.1262,
		},
		{
			src:           "::ffff:10.55.100.110",
			dst:           "::ffff:40.77.229.82",
			totalDuration: 86160.1197,
		},
	}
	// bottom 3 (total duration) over 5hr threshold
	bottomThree := []testCase{
		{
			src:           "::ffff:10.55.100.111",
			dst:           "::ffff:34.196.128.45",
			totalDuration: 18015.6872,
		},
		{
			src:           "::ffff:10.55.100.106",
			dst:           "::ffff:34.196.128.45",
			totalDuration: 18055.099200000008,
		},
		{
			src:           "::ffff:10.55.100.104",
			dst:           "::ffff:172.217.8.196",
			totalDuration: 18145.25299999999,
		},
	}
	type result struct {
		Src      string  `ch:"src"`
		Dst      string  `ch:"dst"`
		TotalDur float64 `ch:"total_duration"`
	}

	t.Run("Top 3 Long Connections", func(t *testing.T) {
		var res []result
		err := it.db.Conn.Select(it.db.GetContext(), &res, `
			SELECT IPv6NumToString(src) as src, IPv6NumToString(dst) as dst, sumMerge(total_duration) as total_duration FROM uconn
			GROUP BY src, dst
			ORDER BY total_duration DESC LIMIT 3
		`)
		require.NoError(t, err)
		require.Len(t, res, len(topThree), "length of result list should match expected value")
		for i, r := range res {
			require.Equal(t, topThree[i].src, r.Src, "uconn: total duration should match (top #%d src: %s, fqdn: %s)", i, topThree[i].src, topThree[i].dst)
			require.Equal(t, topThree[i].dst, r.Dst, "uconn: total duration should match (bottom #%d src: %s, fqdn: %s)", i, topThree[i].src, topThree[i].dst)
			require.InEpsilon(t, topThree[i].totalDuration, r.TotalDur, 0.3, "uconn: total duration should match (top #1%d src: %s, fqdn: %s, duration: %f)", i, topThree[i].src, topThree[i].dst, topThree[i].totalDuration)
		}
	})

	t.Run("Bottom 3 Long Connections >5hrs", func(t *testing.T) {
		var res []result
		err := it.db.Conn.Select(it.db.GetContext(), &res, `
			SELECT * FROM (
				SELECT IPv6NumToString(src) as src, IPv6NumToString(dst) as dst, sumMerge(total_duration) as total_duration FROM uconn
				GROUP BY src, dst
			)
			WHERE total_duration > 18000
			ORDER BY total_duration ASC LIMIT 3
		`)
		require.NoError(t, err)
		require.Len(t, res, len(bottomThree), "length of result list should match expected value")
		for i, r := range res {
			require.Equal(t, bottomThree[i].src, r.Src, "uconn: total duration should match (bottom #%d src: %s, fqdn: %s)", i, bottomThree[i].src, bottomThree[i].dst)
			require.Equal(t, bottomThree[i].dst, r.Dst, "uconn: total duration should match (bottom #%d src: %s, fqdn: %s)", i, bottomThree[i].src, bottomThree[i].dst)
			require.InEpsilon(t, bottomThree[i].totalDuration, r.TotalDur, 0.3, "uconn: total duration should match (bottom #1%d src: %s, fqdn: %s)", i, bottomThree[i].src, bottomThree[i].dst)
		}
	})
}
