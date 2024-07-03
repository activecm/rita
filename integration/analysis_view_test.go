package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/activecm/rita/v5/modifier"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
)

// TestRareSignatures tests the rare_signatures table
func (it *ValidDatasetTestSuite) TestRareSignatures() {
	type signatureRecord struct {
		Signature     string `ch:"signature"`
		TimesUsedDst  uint64 `ch:"times_used_dst"`
		TimesUsedFqdn uint64 `ch:"times_used_fqdn"`
	}

	tests := []struct {
		name             string
		logDir           string
		src              string
		ja3Records       []signatureRecord
		useragentRecords []signatureRecord
	}{
		{
			name:   "Both Useragent and JA3",
			logDir: "../test_data/valid_tsv",
			src:    "10.55.100.104",
			useragentRecords: []signatureRecord{
				{"Microsoft-CryptoAPI/10.0", 19, 24},
				{"Microsoft-Delivery-Optimization/10.0", 2, 4},
				{"Microsoft-WNS/10.0", 7, 1},
				{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", 324, 145},
				{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko", 3, 3},
				{"Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98", 4, 1},
				{"Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.70", 1, 1},
			},
			ja3Records: []signatureRecord{
				{"0eecb7b1551fba4ec03851810d31743f", 1, 1},
				{"10ee8d30a5d01c042afd7b2b205facc4", 987, 501},
				{"3b5074b1b5d032e5620f69f9f700ff0e", 7, 6},
				{"54328bd36c14bd82ddaa0c04b25ed9ad", 4, 1},
				{"a0e9f5d64349fb13191bc781f81f42e1", 2, 2},
				{"bd0bf25947d4a37404f0424edf4db9ad", 31, 23},
				{"ce5f3254611a8c095a3d821d44539877", 6, 2},
				{"f8128c51dc8d1f49da1d6126735300d5", 13, 5},
			},
		},
		{
			name:   "Both Useragent and JA3",
			logDir: "../test_data/valid_tsv",
			src:    "10.55.100.100",
			useragentRecords: []signatureRecord{
				{"Microsoft-CryptoAPI/10.0", 19, 26},
				{"Microsoft-Delivery-Optimization/10.0", 6, 6},
				{"Microsoft-WNS/10.0", 6, 1},
				{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", 366, 185},
				{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko", 4, 4},
				{"Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98", 4, 1},
				{"Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.70", 2, 1},
			},
			ja3Records: []signatureRecord{
				{"0eecb7b1551fba4ec03851810d31743f", 1, 1},
				{"10ee8d30a5d01c042afd7b2b205facc4", 1031, 547},
				{"54328bd36c14bd82ddaa0c04b25ed9ad", 4, 1},
				{"a0e9f5d64349fb13191bc781f81f42e1", 2, 2},
				{"b89be837a4a296476fcd758189908728", 1, 1},
				{"bd0bf25947d4a37404f0424edf4db9ad", 34, 25},
				{"ce5f3254611a8c095a3d821d44539877", 6, 2},
				{"f8128c51dc8d1f49da1d6126735300d5", 12, 6},
			},
		},
		{
			name:   "Both Useragent and JA3",
			logDir: "../test_data/valid_tsv",
			src:    "10.55.100.111",
			useragentRecords: []signatureRecord{
				{"MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT", 2, 2},
				{"Microsoft-CryptoAPI/10.0", 21, 28},
				{"Microsoft-Delivery-Optimization/10.0", 1, 2},
				{"Microsoft-WNS/10.0", 10, 2},
				{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", 307, 178},
				{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko", 3, 2},
				{"Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98", 4, 1},
				{"Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.70", 1, 1},
			},
			ja3Records: []signatureRecord{
				{"0eecb7b1551fba4ec03851810d31743f", 1, 1},
				{"10ee8d30a5d01c042afd7b2b205facc4", 1486, 679},
				{"3b5074b1b5d032e5620f69f9f700ff0e", 2, 2},
				{"54328bd36c14bd82ddaa0c04b25ed9ad", 4, 1},
				{"a0e9f5d64349fb13191bc781f81f42e1", 2, 2},
				{"b89be837a4a296476fcd758189908728", 3, 3},
				{"bd0bf25947d4a37404f0424edf4db9ad", 25, 17},
				{"ce5f3254611a8c095a3d821d44539877", 6, 1},
				{"f8128c51dc8d1f49da1d6126735300d5", 14, 6},
			},
		},
		{
			name:             "JA3 Only",
			logDir:           "../test_data/valid_tsv",
			src:              "192.168.88.2",
			useragentRecords: nil,
			ja3Records: []signatureRecord{
				{"08bf94d7f3200a537b5e3b76b06e02a2", 1, 1},
			},
		},
	}

	for _, test := range tests {
		it.Run(test.name+" "+test.src, func() {
			t := it.T()

			ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
				"src": test.src,
			}))

			t.Run("Useragent", func(t *testing.T) {
				var res []signatureRecord

				// query the rare_signatures table for the given src and is_ja3 = false
				err := it.db.Conn.Select(ctx, &res, `
				SELECT signature, uniqExactMerge(times_used_dst) as times_used_dst, uniqExactMerge(times_used_fqdn) as times_used_fqdn FROM rare_signatures
				WHERE src=={src:String} AND is_ja3==false
				GROUP BY src, src_nuid, signature
				`)
				require.NoError(t, err, "querying rare_signatures table should not produce an error")

				// ensure that the length of the result list matches the expected value
				require.Len(t, res, len(test.useragentRecords), "length of result list should match expected value")

				// ensure that the result list matches the expected value
				require.ElementsMatch(t, test.useragentRecords, res, "result list should match expected value")
			})

			t.Run("JA3", func(t *testing.T) {
				var res []signatureRecord

				// query the rare_signatures table for the given src and is_ja3 = true
				err := it.db.Conn.Select(ctx, &res, `
				SELECT signature, uniqExactMerge(times_used_dst) as times_used_dst, uniqExactMerge(times_used_fqdn) as times_used_fqdn FROM rare_signatures
				WHERE src=={src:String} AND is_ja3==true
				GROUP BY src, src_nuid, signature
				`)
				require.NoError(t, err, "querying rare_signatures table should not produce an error")

				// ensure that the length of the result list matches the expected value
				require.Len(t, res, len(test.ja3Records), "length of result list should match expected value")

				// ensure that the result list matches the expected value
				require.ElementsMatch(t, test.ja3Records, res, "result list should match expected value")

			})
		})
	}
}

/*
check if ip is associated with an fqdn and won't be in threat mixtape:
(if a row is returned, the ip is associated with an fqdn)
	select src, dst, count() as count
	from chickenstrip4.conn
	//inner JOIN chickenstrip4.http USING zeek_uid  -- for http
	inner JOIN chickenstrip4.ssl USING zeek_uid     -- for ssl
	group by src, dst
	having src='192.168.88.2' and dst='165.227.88.15' -- btw these can be WHERE bc it's not an aggregation function, having is for HAVING sum(bytes) > 0
	//having src='10.55.100.111' and dst='24.220.113.59'
*/

func (it *ValidDatasetTestSuite) TestPortInfoTable() {

	type protoInfo struct {
		PortProtoService string `ch:"port_proto_service"`
		ConnCount        uint64 `ch:"conn_count"`
		BytesSent        int64  `ch:"bytes_sent"`
		BytesReceived    int64  `ch:"bytes_received"`
	}

	// make sure table values are getting populated correctly from the multiple materialized views
	it.Run("MV Populated Values", func() {
		tests := []struct {
			name              string
			src               string
			dst               string
			fqdn              string
			portInfoList      []protoInfo
			shouldBeInMixtape bool
		}{
			{
				name: "IP - conn http ssl 1",
				src:  "10.55.100.111",
				dst:  "24.220.113.59",
				portInfoList: []protoInfo{
					// 15 + 2 + 32 + 33 = 82 connections total
					// 9830 + 13500 + 28638275 + 854620 = 29516225 bytes received total
					// 4260 + 0 + 181628 + 52057 = 237945 bytes sent total
					// 29516225 + 237945 = 29754170 total bytes
					{"80:tcp:", 15, 4260, 9830},
					{"443:tcp:", 2, 0, 13500},
					{"443:tcp:ssl", 32, 181628, 28638275},
					{"80:tcp:http", 33, 52057, 854620},
				},
				shouldBeInMixtape: false, // associated with fqdn
			},
			{
				name: "IP - conn http ssl 1",
				src:  "10.55.100.111",
				dst:  "162.208.22.39",
				portInfoList: []protoInfo{
					{"80:tcp:", 4, 160, 0},
					{"443:tcp:", 22, 0, 2654},
					{"443:tcp:ssl", 17, 27970, 62243},
					{"80:tcp:http", 2, 2147, 1745},
				},
				shouldBeInMixtape: false, // associated with fqdn
			},
			{
				name: "IP - conn http ssl 2",
				src:  "10.55.100.105",
				dst:  "192.132.33.27",
				portInfoList: []protoInfo{
					{"80:tcp:", 22, 880, 0},
					{"443:tcp:", 2, 80, 0},
					{"443:tcp:ssl", 2, 2625, 12645},
					{"80:tcp:http", 15, 21367, 11705},
				},
				shouldBeInMixtape: false, // associated with fqdn
			},
			{
				name: "IP - conn 1",
				src:  "10.55.100.111",
				dst:  "165.227.216.194",
				portInfoList: []protoInfo{
					{"443:tcp:", 20054, 1042860, 802160},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn 2",
				src:  "10.55.182.100",
				dst:  "173.243.138.98",
				portInfoList: []protoInfo{
					{"80:tcp:", 4, 312, 0},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn 3",
				src:  "10.55.182.100",
				dst:  "96.45.33.73",
				portInfoList: []protoInfo{
					{"8888:udp:", 1424, 140151, 93828},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn dns 1",
				src:  "192.168.88.2",
				dst:  "165.227.88.15",
				portInfoList: []protoInfo{
					{"53:tcp:", 2, 120, 80},
					{"53:udp:dns", 108856, 9780152, 11945319},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn dns 2",
				src:  "10.55.200.10",
				dst:  "217.70.179.1",
				portInfoList: []protoInfo{
					{"53:udp:dns", 4, 300, 552},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn dns 3",
				src:  "10.55.200.10",
				dst:  "216.239.34.10",
				portInfoList: []protoInfo{
					{"53:udp:dns", 3856, 289630, 388326},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn dns 4",
				src:  "10.55.200.11",
				dst:  "205.251.198.178",
				portInfoList: []protoInfo{
					{"53:udp:dns", 213, 15458, 54195},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "IP - conn ssl 1",
				src:  "10.55.182.100",
				dst:  "172.217.8.206",
				portInfoList: []protoInfo{
					// 8 connections total
					// 7711 + 172 + 5269 = 13152 bytes received total
					// 8163 + 92 + 22271 = 30526 bytes sent total
					// 13152 + 30526 = 43678 total bytes
					{"443:udp:", 3, 7711, 8163},
					{"443:tcp:", 1, 172, 92},
					{"443:tcp:ssl", 4, 5269, 22271},
				},
				shouldBeInMixtape: false,
			},
			{
				name: "FQDN - http ssl 1",
				src:  "10.55.100.103",
				fqdn: "code.jquery.com",
				portInfoList: []protoInfo{
					{"443:tcp:ssl", 3, 5707, 102655},
					{"80:tcp:http", 1, 720, 39328},
				},
				shouldBeInMixtape: false, // not enough unique timestamps
			},
			{
				src:  "10.55.100.103",
				fqdn: "geo-um.btrll.com",
				portInfoList: []protoInfo{
					{"443:tcp:ssl", 23, 50397, 95507},
					{"80:tcp:http", 2, 2689, 2039},
				},
				shouldBeInMixtape: true,
			},
			{
				name: "FQDN - ssl 1",
				src:  "10.55.100.110",
				fqdn: "g.live.com",
				portInfoList: []protoInfo{
					{"443:tcp:ssl", 4, 4942, 20158},
				},
				shouldBeInMixtape: true,
			},
		}

		for _, test := range tests {

			it.Run(test.name, func() {
				t := it.T()

				// update pair and pairField based on whether we are querying by dst or fqdn
				pair := test.dst
				pairField := "dst"
				if test.fqdn != "" {
					pair = test.fqdn
					pairField = "fqdn"
				}

				// set the context parameters
				ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
					"src":        test.src,
					"pair":       pair,
					"pair_field": pairField,
				}))

				t.Run("Check Values", func(t *testing.T) {

					// query the proto table for the given src and dst/fqdn
					var res []protoInfo
					err := it.db.Conn.Select(ctx, &res, `
						SELECT concat(dst_port, ':', proto, ':', service) AS port_proto_service,
							countMerge(count) AS conn_count,
							sumMerge(bytes_sent) AS bytes_sent,
							sumMerge(bytes_received) AS bytes_received
						FROM port_info
						where src={src:String} and {pair_field:Identifier}={pair:String}
						GROUP BY src, dst, fqdn, dst_port, proto, service
					`)
					require.NoError(t, err, "querying proto table should not produce an error")

					// ensure that the length of the result list matches the expected value
					require.Len(t, res, len(test.portInfoList), "length of result list should match expected value")

					// ensure that the result list matches the expected value
					require.ElementsMatch(t, test.portInfoList, res, "result list should match expected value")
				})

				t.Run("Threat Mixtape Propagation", func(t *testing.T) {
					// vet that entries that make it to the threat_mixtape table have all the port-proto-service info from the proto_info table

					type protoInfo2 struct {
						PortProtoServices []string `ch:"port_proto_service"`
						ConnCount         uint64   `ch:"count"`
						OpenCount         uint64   `ch:"open_count"`
						TotalBytes        uint64   `ch:"total_bytes"`
					}

					// query the threat mixtape for the given src and dst/fqdn
					var res2 protoInfo2
					err := it.db.Conn.QueryRow(ctx, `
						SELECT --src, {pair_field:Identifier},
							port_proto_service, 
							count,
							open_count,
							total_bytes,
						FROM threat_mixtape
						where src={src:String} and {pair_field:Identifier}={pair:String} 
						--  and count > 0 
						and length(port_proto_service) > 0
					`).ScanStruct(&res2)

					// check that threat mixtape entry is present or absent based on test
					if test.shouldBeInMixtape {
						require.NoError(t, err, "querying threat mixtape should not produce an error")
						// verify result is not empty
						require.NotEmpty(t, res2, "result should not be empty")

						// get list of port-proto-services
						var portProtoServices []string
						connCount := uint64(0)
						openCount := uint64(0)
						totalBytes := uint64(0)
						for _, p := range test.portInfoList {
							portProtoServices = append(portProtoServices, p.PortProtoService)
							connCount += p.ConnCount
							openCount += p.ConnCount // the test log's open conn log is exactly the same as conn
							totalBytes += uint64(p.BytesSent + p.BytesReceived)
						}

						// vet list of port-proto-services
						require.ElementsMatch(t, portProtoServices, res2.PortProtoServices, "port-proto-services should match")

						// vet conn count
						require.EqualValues(t, connCount, res2.ConnCount, "conn count should match")

						// vet open count (open_conn.log is identical to conn.log in the test data. We keep its count, but do not
						// keep the bytes info like we do for conn.log)
						require.EqualValues(t, int64(connCount), int64(res2.OpenCount), "open count should match")

						// vet total bytes (multiplied by 2 because threat mixtape includes open conns and since that log is identical to conn.log
						// in the test data, the total bytes is doubled)
						require.EqualValues(t, int64(totalBytes)*2, int64(res2.TotalBytes), "total bytes should match")
					} else {
						if errors.Is(err, sql.ErrNoRows) {
							// This is expected, as we should not find any rows
							err = nil
						}
						require.NoError(t, err, "querying threat_mixtape table should not produce an error")
						require.Empty(t, res2, "no result is expected")
					}

				})
			})
		}
	})

}

func (it *ValidDatasetTestSuite) TestTLSProtoTable() {

	type protoInfo struct {
		JA3              string `ch:"ja3"`
		Version          string `ch:"version"`
		ValidationStatus string `ch:"validation_status"`
		Count            uint64 `ch:"count"`
	}

	tests := []struct {
		name          string
		src           string
		fqdn          string
		protoInfoList []protoInfo
	}{
		{
			name: "Single Entry 1",
			src:  "10.55.100.107",
			fqdn: "comet.yahoo.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 19},
			},
		},
		{
			name: "Single Entry 2",
			src:  "10.55.100.107",
			fqdn: "www.googletagmanager.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 84},
			},
		},
		{
			name: "Single Entry 3",
			src:  "10.55.100.110",
			fqdn: "www.facebook.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 152},
			},
		},
		{
			name: "Multiple Entries 1",
			src:  "10.55.100.111",
			fqdn: "ml314.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 41},
				{"b89be837a4a296476fcd758189908728", "TLSv10", "", 1},
				{"b89be837a4a296476fcd758189908728", "TLSv10", "ok", 1},
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "", 87},
				{"10ee8d30a5d01c042afd7b2b205facc4", "", "", 1},
			},
		},
		{
			name: "Multiple Entries 2",
			src:  "10.55.100.100",
			fqdn: "oneclient.sfx.ms",
			protoInfoList: []protoInfo{
				{"a0e9f5d64349fb13191bc781f81f42e1", "TLSv12", "", 1},
				{"bd0bf25947d4a37404f0424edf4db9ad", "TLSv12", "ok", 2},
				{"a0e9f5d64349fb13191bc781f81f42e1", "TLSv12", "ok", 1},
			},
		},
		{
			name: "Multiple Entries 3",
			src:  "10.55.100.109",
			fqdn: "pixel.adsafeprotected.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 26},
				{"10ee8d30a5d01c042afd7b2b205facc4", "", "", 2},
			},
		},
		{
			name: "Status != ok",
			src:  "10.55.100.106",
			fqdn: "settings-win.data.microsoft.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "unable to get local issuer certificate", 3},
				{"bd0bf25947d4a37404f0424edf4db9ad", "TLSv12", "unable to get local issuer certificate", 69},
			},
		},
		{
			name: "High Count",
			src:  "10.55.100.108",
			fqdn: "www.alexa.com",
			protoInfoList: []protoInfo{
				{"10ee8d30a5d01c042afd7b2b205facc4", "TLSv12", "ok", 21},
				{"54328bd36c14bd82ddaa0c04b25ed9ad", "TLSv10", "ok", 290},
			},
		},
	}

	for _, test := range tests {
		it.Run(test.name, func() {
			t := it.T()

			// create a hash for the given src and fqdn
			hash, err := util.NewFixedStringHash(test.src, util.UnknownPrivateNetworkUUID.String(), test.fqdn)
			require.NoError(t, err, "creating hash should not produce an error")

			// set the context parameters
			ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
				"src":  test.src,
				"hash": hash.Hex(),
			}))

			// query the proto table for the given src and dst/fqdn
			var res []protoInfo
			err = it.db.Conn.Select(ctx, &res, `
				SELECT ja3, version, validation_status, countMerge(count) as count FROM tls_proto
				WHERE hash=unhex({hash:String})
				GROUP BY hash, ja3, version, validation_status
			`)
			require.NoError(t, err, "querying proto table should not produce an error")

			// ensure that the length of the result list matches the expected value
			require.Len(t, res, len(test.protoInfoList), "length of result list should match expected value")

			// ensure that the result list matches the expected value
			require.ElementsMatch(t, test.protoInfoList, res, "result list should match expected value")

		})
	}
}

func (it *ValidDatasetTestSuite) TestHTTPProtoTable() {

	type protoInfo struct {
		Useragent    string   `ch:"useragent"`
		Method       string   `ch:"method"`
		Referrer     string   `ch:"referrer"`
		URI          string   `ch:"uri"`
		DstMimeTypes []string `ch:"dst_mime_types"`
		Count        uint64   `ch:"count"`
	}

	tests := []struct {
		name          string
		src           string
		fqdn          string
		protoInfoList []protoInfo
	}{
		{
			name: "Single Entry",
			src:  "10.55.100.104",
			fqdn: "cdn.taboola.com",
			protoInfoList: []protoInfo{
				{
					Useragent:    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
					Method:       "GET",
					URI:          "/libtrc/businessinsider/loader.js",
					Referrer:     "http://www.businessinsider.com/",
					DstMimeTypes: []string{"text/plain"},
					Count:        16,
				},
			},
		},

		{
			name: "Multiple Entries",
			src:  "10.55.100.107",
			fqdn: "www.google.com",
			protoInfoList: []protoInfo{
				{
					Useragent:    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
					Method:       "GET",
					URI:          "/ads/user-lists/863238793/?guid=ON&script=0&cdct=2&is_vtc=1&random=2136862691",
					Referrer:     "http://www.fedex.com/",
					DstMimeTypes: []string{"image/gif"},
					Count:        1,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
					Method:       "GET",
					URI:          "/ads/user-lists/863238793/?guid=ON&script=0&cdct=2&is_vtc=1&random=3719609297",
					Referrer:     "http://www.fedex.com/",
					DstMimeTypes: []string{"image/gif"},
					Count:        1,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
					Method:       "GET",
					URI:          "/ads/user-lists/863238793/?guid=ON&script=0&cdct=2&is_vtc=1&random=4251233521",
					Referrer:     "http://www.fedex.com/",
					DstMimeTypes: []string{"image/gif"},
					Count:        1,
				},
			},
		},
		{
			name: "Multiple Unique MIME Types",
			src:  "10.55.100.109",
			fqdn: "imasdk.googleapis.com",
			protoInfoList: []protoInfo{
				{
					Useragent:    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
					Method:       "GET",
					URI:          "/js/sdkloader/ima3.js",
					Referrer:     "http://www.businessinsider.com/",
					DstMimeTypes: []string{"text/plain", "application/javascript"},
					Count:        14,
				},
			},
		},
		{
			name: "Empty Referrer",
			src:  "10.55.100.105",
			fqdn: "www.alexa.com",
			protoInfoList: []protoInfo{
				{
					Useragent:    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98",
					Method:       "GET",
					URI:          "/topsites/category;2/Top/Business/",
					DstMimeTypes: []string{"text/html"},
					Count:        71,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98",
					Method:       "GET",
					URI:          "/topsites/category;1/Top/Business/",
					DstMimeTypes: []string{"text/html"},
					Count:        62,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98",
					Method:       "GET",
					URI:          "/topsites/category;4/Top/Business/",
					DstMimeTypes: []string{"text/html"},
					Count:        60,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98",
					Method:       "GET",
					URI:          "/topsites/category;0/Top/Business/",
					DstMimeTypes: []string{"text/html"},
					Count:        45,
				},
				{
					Useragent:    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98",
					Method:       "GET",
					URI:          "/topsites/category;3/Top/Business/",
					DstMimeTypes: []string{"text/html"},
					Count:        50,
				},
			},
		},
		{
			name: "MIME Types Empty",
			src:  "10.55.100.107",
			fqdn: "ctldl.windowsupdate.com",
			protoInfoList: []protoInfo{
				{
					Useragent:    "Microsoft-CryptoAPI/10.0",
					Method:       "GET",
					URI:          "/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?40f9d126e5b63a43",
					Referrer:     "",
					DstMimeTypes: []string{},
					Count:        1,
				},
				{
					Useragent:    "Microsoft-CryptoAPI/10.0",
					Method:       "GET",
					URI:          "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?525cb8ffc6c284d5",
					Referrer:     "",
					DstMimeTypes: []string{},
					Count:        1,
				},
				{
					Useragent:    "Microsoft-CryptoAPI/10.0",
					Method:       "GET",
					URI:          "/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?52033f8ab02770a1",
					Referrer:     "",
					DstMimeTypes: []string{},
					Count:        1,
				},
			},
		},
	}

	for _, test := range tests {
		it.Run(test.name, func() {
			t := it.T()

			// create a hash for the given src and fqdn
			hash, err := util.NewFixedStringHash(test.src, util.UnknownPrivateNetworkUUID.String(), test.fqdn)
			require.NoError(t, err, "creating hash should not produce an error")

			// set the context parameters
			ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
				"src":  test.src,
				"hash": hash.Hex(),
			}))

			// import the data

			// query the proto table for the given src and fqdn
			var res []protoInfo
			err = it.db.Conn.Select(ctx, &res, `
					SELECT useragent, 
						   method,
						   referrer,
						   uri,
						   groupUniqArrayMerge(dst_mime_types) AS dst_mime_types,
						   countMerge(count) as count FROM http_proto
					where hash=unhex({hash:String})
					GROUP BY hash, useragent, method, referrer, uri
				`)
			require.NoError(t, err, "querying proto table should not produce an error")

			// ensure that the length of the result list matches the expected value
			require.Len(t, res, len(test.protoInfoList), "length of result list should match expected value")

			// ensure that the result list matches the expected value
			require.ElementsMatch(t, test.protoInfoList, res, "result list should match expected value")
		})
	}

}

func (it *ValidDatasetTestSuite) TestMimeTypesURIsTable() {

	type mimeTypesURIInfo struct {
		URI           string `ch:"uri"`
		Path          string `ch:"path"`
		Extension     string `ch:"extension"`
		MimeType      string `ch:"mime_type"`
		MismatchCount uint64 `ch:"mismatch_count"`
	}

	type modifierInfo struct {
		ModifierName  string  `ch:"modifier_name"`
		ModifierScore float32 `ch:"modifier_score"`
		ModifierValue string  `ch:"modifier_value"`
	}

	tests := []struct {
		name                 string
		src                  string
		fqdn                 string
		mimeTypesURIInfoList []mimeTypesURIInfo
	}{
		{
			name: "Single Entry",
			src:  "10.55.100.103",
			fqdn: "ml314.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/tag.aspx?3102018",
					Path:          "/tag.aspx",
					Extension:     "aspx",
					MimeType:      "text/plain",
					MismatchCount: 3,
				},
			},
		},
		{
			name: "Multiple Entries",
			src:  "10.55.100.104",
			fqdn: "a.scorecardresearch.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/rpc.flow?uid=uid1517427661057&ns_mod_ns=mvce&ns__p=1517427661054&ns__t=1517427661054&ns__c=utf-8&ns_ad_conn=true|undefined&c1=3&c3=20577465&c4=97390356&c5=211121863&c6=&c10=1&c11=936679&c13=320x50&c16=dcm&c2=26816564&ax_iframe=1&ns_ce_sv=5.1710.03&ns_ce_mod=vce_st&ns_ad_event=load&c8=&c7=http://www.espn.com/&c9=",
					Path:          "/rpc.flow",
					Extension:     "flow",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
				{
					URI:           "/rpc.flow?uid=uid1517432161482&ns_mod_ns=mvce&ns__p=1517432161476&ns__t=1517432161476&ns__c=utf-8&ns_ad_conn=true|undefined&c1=3&c3=20577465&c4=97390356&c5=211121863&c6=&c10=1&c11=936679&c13=320x50&c16=dcm&c2=26816564&ax_iframe=1&ns_ce_sv=5.1710.03&ns_ce_mod=vce_st&ns_ad_event=load&c8=&c7=http://www.espn.com/&c9=",
					Path:          "/rpc.flow",
					Extension:     "flow",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
				{
					URI:           "/rpc.flow?uid=uid1517433060023&ns_mod_ns=mvce&ns__p=1517433060017&ns__t=1517433060017&ns__c=utf-8&ns_ad_conn=true|undefined&c1=3&c3=20577465&c4=97390356&c5=211121863&c6=&c10=1&c11=936679&c13=320x50&c16=dcm&c2=26816564&ax_iframe=1&ns_ce_sv=5.1710.03&ns_ce_mod=vce_st&ns_ad_event=load&c8=&c7=http://www.espn.com/&c9=",
					Path:          "/rpc.flow",
					Extension:     "flow",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
				{
					URI:           "/rpc.flow?uid=uid1517441160618&ns_mod_ns=mvce&ns__p=1517441160615&ns__t=1517441160615&ns__c=utf-8&ns_ad_conn=true|undefined&c1=3&c3=20577465&c4=97390356&c5=211121863&c6=&c10=1&c11=936679&c13=320x50&c16=dcm&c2=26816564&ax_iframe=1&ns_ce_sv=5.1710.03&ns_ce_mod=vce_st&ns_ad_event=load&c8=&c7=http://www.espn.com/&c9=",
					Path:          "/rpc.flow",
					Extension:     "flow",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
				{
					URI:           "/rpc.flow?uid=uid1517436360940&ns_mod_ns=mvce&ns__p=1517436360935&ns__t=1517436360935&ns__c=utf-8&ns_ad_conn=true|undefined&c1=3&c3=20577465&c4=97390356&c5=211121863&c6=&c10=1&c11=936679&c13=320x50&c16=dcm&c2=26816564&ax_iframe=1&ns_ce_sv=5.1710.03&ns_ce_mod=vce_st&ns_ad_event=load&c8=&c7=http://www.espn.com/&c9=",
					Path:          "/rpc.flow",
					Extension:     "flow",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
			},
		},
		{
			name: "Extensions in URIs",
			src:  "10.55.100.107",
			fqdn: "static.adsafeprotected.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/main.17.4.65.js",
					Path:          "/main.17.4.65.js",
					Extension:     "js",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
				{
					URI:           "/main.17.4.64.js",
					Path:          "/main.17.4.64.js",
					Extension:     "js",
					MimeType:      "text/plain",
					MismatchCount: 1,
				},
			},
		},
		{
			name: "No Extensions in URIs",
			src:  "10.55.100.108",
			fqdn: "www.businessinsider.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/esi/user_menubar?0=json:[]&1=NULL",
					Path:          "/esi/user_menubar",
					Extension:     "",
					MimeType:      "text/plain",
					MismatchCount: 17,
				},
				{
					URI:           "/esi/ed_sidebar",
					Path:          "/esi/ed_sidebar",
					Extension:     "",
					MimeType:      "text/plain",
					MismatchCount: 17,
				},
			},
		},
		{
			name: "Variety of Extensions in URIs",
			src:  "10.55.100.105",
			fqdn: "static1.businessinsider.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/assets/js/min-foot.js?1517260501",
					Path:          "/assets/js/min-foot.js",
					Extension:     "js",
					MimeType:      "text/plain",
					MismatchCount: 12,
				},
				{
					URI:           "/public/fonts/LabGrotesque-Regular.woff",
					Path:          "/public/fonts/LabGrotesque-Regular.woff",
					Extension:     "woff",
					MimeType:      "text/html",
					MismatchCount: 12,
				},
				{
					URI:           "/assets/css/min-base-us.css?1517260501",
					Path:          "/assets/css/min-base-us.css",
					Extension:     "css",
					MimeType:      "text/plain",
					MismatchCount: 12,
				},
			},
		},
		{
			name: "High MisMatch Counts",
			src:  "10.55.100.106",
			fqdn: "www.alexa.com",
			mimeTypesURIInfoList: []mimeTypesURIInfo{
				{
					URI:           "/topsites/category;3/Top/Business/",
					Path:          "/topsites/category;3/Top/Business/",
					Extension:     "",
					MimeType:      "text/html",
					MismatchCount: 61,
				},
				{
					URI:           "/topsites/category;0/Top/Business/",
					Path:          "/topsites/category;0/Top/Business/",
					Extension:     "",
					MimeType:      "text/html",
					MismatchCount: 63,
				},
				{
					URI:           "/topsites/category;2/Top/Business/",
					Path:          "/topsites/category;2/Top/Business/",
					Extension:     "",
					MimeType:      "text/html",
					MismatchCount: 67,
				},
				{
					URI:           "/topsites/category;1/Top/Business/",
					Path:          "/topsites/category;1/Top/Business/",
					Extension:     "",
					MimeType:      "text/html",
					MismatchCount: 53,
				},
				{
					URI:           "/topsites/category;4/Top/Business/",
					Path:          "/topsites/category;4/Top/Business/",
					Extension:     "",
					MimeType:      "text/html",
					MismatchCount: 44,
				},
			},
		},
	}

	for _, test := range tests {

		// check mime types uris table values
		it.Run(test.name, func() {
			t := it.T()

			// create a hash for the given src and fqdn
			hash, err := util.NewFixedStringHash(test.src, util.UnknownPrivateNetworkUUID.String(), test.fqdn)
			require.NoError(t, err, "creating hash should not produce an error")

			// set the context parameters
			ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
				"hash":          hash.Hex(),
				"modifier_name": modifier.MIME_TYPE_MISMATCH_MODIFIER_NAME,
			}))

			t.Run("Verify Values", func(t *testing.T) {
				// query the proto table for the given src and fqdn
				var res []mimeTypesURIInfo
				err = it.db.Conn.Select(ctx, &res, `
					SELECT uri, 
						   path,
						   extension,
						   mime_type,
						   countMerge(mismatch_count) as mismatch_count 
					FROM mime_type_uris
					WHERE hash=unhex({hash:String})
					GROUP BY hash, uri, path, extension, mime_type
				`)
				require.NoError(t, err, "querying mime_type_uris table should not produce an error")

				// ensure that the length of the result list matches the expected value
				require.Len(t, res, len(test.mimeTypesURIInfoList), "length of result list should match expected value")

				// ensure that the result list matches the expected value
				require.ElementsMatch(t, test.mimeTypesURIInfoList, res, "result list should match expected value")
			})

			// check threat mixtape table modifier entry
			t.Run("Verify Modifier", func(t *testing.T) {
				// query the threat_mixtape table for the given hash and modifier name
				var res2 modifierInfo
				err = it.db.Conn.QueryRow(ctx, `
					SELECT modifier_name, modifier_score, modifier_value
					FROM threat_mixtape
					WHERE hash=unhex({hash:String}) AND modifier_name={modifier_name:String}
				`).ScanStruct(&res2)

				// verify that the query did not produce an error and that the result is not empty
				require.NoError(t, err, "querying threat_mixtape table should not produce an error")
				require.NotEmpty(t, res2, "result should not be empty")

				// check score was set correctly based on config
				require.InDelta(t, it.cfg.Modifiers.MIMETypeMismatchScoreIncrease, res2.ModifierScore, 0.001, "modifier score must match expected value")

				// verify that modifier value is equal to the sum of all the mismatch counts
				var sum uint64
				for _, info := range test.mimeTypesURIInfoList {
					sum += info.MismatchCount
				}
				modifierValue, err := strconv.Atoi(res2.ModifierValue)
				require.NoError(t, err, "modifier value must be able to be converted to an integer")
				require.EqualValues(t, sum, modifierValue, "modifier value must match the sum of all mismatch counts")

			})

		})
	}

}

func (it *ValidDatasetTestSuite) TestThreatMixtape() {
	t := it.T()

	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count(DISTINCT hash) FROM threat_mixtape
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 4668, count, "threat mixtape should have 4668 unique hashes, got: %d", count)

	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM threat_mixtape
		WHERE modifier_name = ''
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 4668, count, "threat mixtape should have one non-modifier row per unique hash, got: %d", count)

	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM threat_mixtape
		WHERE beacon_type != 'dns' AND count != open_count
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "open conn count should always match conn count (for non-DNS)")

	minTimestamp, maxTimestamp, _, err := it.db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	chCtx := it.db.QueryParameters(clickhouse.Parameters{
		"min_ts":                    fmt.Sprintf("%d", minTimestamp.UTC().Unix()),
		"max_ts":                    fmt.Sprintf("%d", maxTimestamp.UTC().Unix()),
		"first_seen_increase_score": fmt.Sprintf("%1.3f", it.cfg.Modifiers.FirstSeenScoreIncrease),
		"prevalence_decrease_score": fmt.Sprintf("%1.3f", -it.cfg.Modifiers.PrevalenceScoreDecrease),
		"beacon_none_thresh":        fmt.Sprintf("%1.3f", float32(it.cfg.Scoring.Beacon.ScoreThresholds.Base)/100),
	})
	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE last_seen < {min_ts:Int64} OR last_seen > {max_ts:Int64}
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no entries should have a last seen date less than the min timestamp or greater than the max timestamp")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE modifier_name = '' AND (first_seen_historical < {min_ts:Int64} OR first_seen_historical > {max_ts:Int64})
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no non-modifier entries should have a historical first seen date less than the min timestamp or greater than the max timestamp")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE modifier_name = '' AND first_seen_score != {first_seen_increase_score:Float32}
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no non-modifier entries should have a historical first seen score other than the increase score")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count(DISTINCT import_id) FROM threat_mixtape
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "there should be only one import id")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count(DISTINCT analyzed_at) FROM threat_mixtape
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "there should be only one unique analyzed at timestamp")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE src != '::' AND dst = '::' AND fqdn = ''
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no entries with a src IP should have missing dst IP and missing FQDN")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE beacon_type = 'dns' AND (src != '::' OR dst != '::')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no DNS entries should have a src or dst IP")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE beacon_type = 'sni' AND length(server_ips) = 0
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all SNI entries should have at least 1 server IP")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE beacon_type != '' AND beacon_type != 'dns' AND (count = 0)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all non-DNS (non-modifier) entries should have a connection count")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE count >= 86400 AND strobe_score <= 0
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all strobes should have a strobe score")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE beacon_score >= {beacon_none_thresh:Float32} AND beacon_threat_score <= 0
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all entries with a beacon score should have a beacon threat score")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE modifier_name = '' AND (prevalence_total <= 0 OR prevalence <= 0)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all non-modifier entries should have prevalence set")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE prevalence_total >= 8 AND (prevalence < 0.53333336 OR prevalence_score > {prevalence_decrease_score:Float32})
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all entries with a prevalence total being over 50% (8/15) should have a prevalence of >= 0.53 and prevalence decrease score")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE prevalence_total < 8 AND (prevalence > 0.53333336 OR prevalence_score != 0)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all entries with a prevalence total being under 50% (8/15) should have a prevalence of < 0.53 and prevalence score of 0")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM (
			SELECT src, dst, fqdn, count(hash) as hash_count FROM threat_mixtape
			WHERE beacon_type = 'sni'
			GROUP BY src, dst, fqdn
		) WHERE hash_count != 1
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "each unique SNI connection should use only one unique hash")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM (
			SELECT src, dst, count(hash) as hash_count FROM threat_mixtape
			WHERE beacon_type = 'ip'
			GROUP BY src, dst
		) WHERE hash_count != 1
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "each unique IP connection should use only one unique hash")

	err = it.db.Conn.QueryRow(chCtx, `
		SELECT count() FROM threat_mixtape
		WHERE beacon_type = 'dns' AND hash != MD5(fqdn)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "all dns entries should have a hash that contains only the fqdn")
}

func (it *ValidDatasetTestSuite) TestBigOlHistogramTable() {
	t := it.T()

	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM (
			SELECT import_hour, hash, bucket, src_ip_bytes, countMerge(count) AS c FROM big_ol_histogram
			GROUP BY import_hour, hash, bucket, src_ip_bytes
			HAVING c < 1
		)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "no entries in big_ol_histogram should have a count less than 1")

	type histogram struct {
		Bucket     uint32 `ch:"bucket_ts"`
		SrcIPBytes int64  `ch:"src_ip_bytes"`
		Count      uint64 `ch:"count"`
	}

	testCases := []struct {
		name string
		hash string
		hour int64
		Data []histogram
	}{

		{
			name: "10.55.100.107 -> 23.217.28.150",
			hash: "00281FB4049C4613CA0F4307F7B96932",
			hour: 1517418000,
			Data: []histogram{
				{Bucket: 1517418000, SrcIPBytes: 1691, Count: 3},
				{Bucket: 1517418900, SrcIPBytes: 1600, Count: 2},
				{Bucket: 1517420700, SrcIPBytes: 1599, Count: 2},
			},
		},

		{
			name: "10.55.100.109 -> www.alexa.com (HTTP & SSL)",
			hash: "F9433F6806956E558A72AE934BB7CC4F",
			hour: 1517338800,
			Data: []histogram{
				{Bucket: 1517338800, SrcIPBytes: 7134, Count: 6},
				{Bucket: 1517339700, SrcIPBytes: 6352, Count: 6},
				{Bucket: 1517340600, SrcIPBytes: 7402, Count: 6},
				{Bucket: 1517341500, SrcIPBytes: 6392, Count: 6},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			var res []histogram
			chCtx := it.db.QueryParameters(clickhouse.Parameters{
				"hash": test.hash,
				"hour": fmt.Sprintf("%d", test.hour),
			})
			err = it.db.Conn.Select(chCtx, &res, `
			SELECT toUnixTimestamp(bucket) as bucket_ts, sum(src_ip_bytes) as src_ip_bytes, countMerge(count) as count FROM big_ol_histogram
			WHERE hash = unhex({hash:String}) AND toStartOfHour(bucket) = fromUnixTimestamp({hour:Int64})
			GROUP BY bucket_ts
			ORDER BY bucket_ts
		`)
			require.NoError(t, err)
			require.Equal(t, test.Data, res)
		})
	}
}
