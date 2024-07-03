package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type NetworkIDSuite ValidDatasetTestSuite

func TestNetworkID(t *testing.T) {
	networkIDSuite := new(NetworkIDSuite)

	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.LoadConfig(afs, ConfigPath)
	require.NoError(t, err)

	cfg.Filter.FilterExternalToInternal = false
	err = config.UpdateConfig(cfg)
	require.NoError(t, err)

	cfg.DBConnection = dockerInfo.clickhouseConnection
	require.NoError(t, err, "updating config should not return an error")

	// // import data
	results, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/dnscat2-ja3-strobe-agent", "dnscat2_ja3_strobe_agent", false, false)
	require.NoError(t, err)
	networkIDSuite.importResults = results

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "dnscat2_ja3_strobe_agent", cfg, nil)
	require.NoError(t, err)

	// determine which max timestamp to use for relative time calculations
	minTimestamp, maxTimestamp, _, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)

	networkIDSuite.maxTimestamp = maxTimestamp
	networkIDSuite.minTimestamp = minTimestamp

	// networkIDSuite.useCurrentTime = useCurrentTime
	networkIDSuite.db = db
	networkIDSuite.cfg = cfg
	suite.Run(t, networkIDSuite)
}

func (it *NetworkIDSuite) TestNetworkIDSeparation() {
	t := it.T()

	expectedSrcNUIDs := map[uuid.UUID][]string{
		// Carol
		uuid.MustParse("5934e4c5-9acb-498f-a706-b4b7200a47aa"): {
			"192.168.88.2", "10.55.200.11", "10.55.182.100", "10.55.100.110", "10.55.100.109",
			"10.55.100.108", "10.55.100.107", "10.55.100.106", "10.55.100.105", "10.55.100.104", "10.55.100.103", "10.55.100.100",
		},
		// Bob
		uuid.MustParse("e59a5fc8-ebf5-4f82-b98e-ab2c7fad6099"): {
			"10.55.100.111",
		},
		// Alice Late
		uuid.MustParse("439264be-a146-4759-80f7-f4fb23b9b346"): {
			"10.55.200.10",
		},
		// Alice Early
		uuid.MustParse("779a5281-949d-4ae3-9de4-309c955f48c0"): {
			"10.55.200.10",
		},
		// external
		uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"): {
			"24.220.6.168", "67.226.210.13", "67.226.210.14", "67.226.210.15", "66.218.84.141", "165.227.88.15",
		},
	}

	// verify that all expected source nuids exist and they have the right src IPs
	rows, err := it.db.Conn.Query(it.db.GetContext(), `--sql
		SELECT src_nuid, groupUniqArray(src) FROM (
			SELECT DISTINCT src_nuid, src FROM conn
			UNION DISTINCT
			SELECT DISTINCT src_nuid, src FROM http
			UNION DISTINCT
			SELECT DISTINCT src_nuid, src FROM ssl
		)
		GROUP BY src_nuid
	`)
	require.NoError(t, err, "retrieving the unique src IPs for each src nuid should not error")

	i := 0
	for rows.Next() {
		var srcNUID uuid.UUID
		var srcIPs []string
		err = rows.Scan(&srcNUID, &srcIPs)
		require.NoError(t, err)
		require.ElementsMatch(t, srcIPs, expectedSrcNUIDs[srcNUID])
		i++
	}
	rows.Close()
	require.EqualValues(t, len(expectedSrcNUIDs), i, "there should be %d unique src_nuids", len(expectedSrcNUIDs))

	// verify that all expected destination nuids exist and have the right destination IPs
	rows, err = it.db.Conn.Query(it.db.GetContext(), `--sql
		SELECT dst_nuid, groupUniqArray(dst) FROM (
			SELECT DISTINCT dst_nuid, dst FROM conn
			UNION DISTINCT
			SELECT DISTINCT dst_nuid, dst FROM http
			UNION DISTINCT
			SELECT DISTINCT dst_nuid, dst FROM ssl
		)
		GROUP BY dst_nuid
	`)
	require.NoError(t, err)
	i = 0
	hadExternalID := false
	for rows.Next() {
		var dstNUID uuid.UUID
		var dstIPs []string
		err = rows.Scan(&dstNUID, &dstIPs)
		require.NoError(t, err)
		if dstNUID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
			hadExternalID = true
		} else {
			require.Equal(t, "5934e4c5-9acb-498f-a706-b4b7200a47aa", dstNUID.String(), "the only other destination NUID should be for Carol")
			require.Subset(t, expectedSrcNUIDs[dstNUID], dstIPs, "the nuid should have the same subset of IPs as the src test")
		}
		i++
	}
	rows.Close()
	require.EqualValues(t, 2, i, "there should be %d unique dst_nuids", 2)
	require.True(t, hadExternalID, "external network ID should have appeared in results")

	// verify the hashes and counts of two src NUIDs that share the same IP to the same destination IP
	type countRes struct {
		Hash    util.FixedString `ch:"hash"`
		SrcNUID uuid.UUID        `ch:"src_nuid"`
		Count   uint64           `ch:"count"`
	}
	hashAliceLate, err := util.NewFixedStringFromHex("4F30F87B8FA6FE9FBCACB8E26D39856D")
	require.NoError(t, err)

	hashAliceEarly, err := util.NewFixedStringFromHex("2A7F3113D298AF443DEEE57096C2BD43")
	require.NoError(t, err)

	expectedCounts := []countRes{
		{Hash: hashAliceEarly, SrcNUID: uuid.MustParse("439264be-a146-4759-80f7-f4fb23b9b346"), Count: 38},
		{Hash: hashAliceLate, SrcNUID: uuid.MustParse("779a5281-949d-4ae3-9de4-309c955f48c0"), Count: 10},
	}
	var res []countRes
	err = it.db.Conn.Select(it.db.GetContext(), &res, `--sql
		SELECT hash, src_nuid, count() as count FROM conn
		WHERE src = '10.55.200.10' AND dst = '205.251.197.234'
		GROUP BY hash, src_nuid
	`)
	require.NoError(t, err, "retrieving the counts for overlapping IPs should not error")

	require.ElementsMatch(t, res, expectedCounts, "overlapping src IP counts and hashes should match")

	hashAliceLate, err = util.NewFixedStringFromHex("D5F03D88ED5204F188E4FCD008D610AB")
	require.NoError(t, err)

	hashAliceEarly, err = util.NewFixedStringFromHex("5089B970C98C14ADB59AB8F1744C5058")
	require.NoError(t, err)

	// verify the hashes and counts of two src NUIDs that share the same IP to the same FQDN
	expectedCounts = []countRes{
		{Hash: hashAliceEarly, SrcNUID: uuid.MustParse("439264be-a146-4759-80f7-f4fb23b9b346"), Count: 14},
		{Hash: hashAliceLate, SrcNUID: uuid.MustParse("779a5281-949d-4ae3-9de4-309c955f48c0"), Count: 5},
	}

	err = it.db.Conn.Select(it.db.GetContext(), &res, `--sql
		SELECT hash, src_nuid, count() as count FROM ssl
		WHERE src = '10.55.200.10' AND server_name = 'fe2.update.microsoft.com'
		GROUP BY hash, src_nuid
	`)
	require.NoError(t, err, "retrieving the counts for overlapping IPs should not error")

	require.ElementsMatch(t, res, expectedCounts, "overlapping src IP counts and hashes should match")

	// make sure there are no overlapping hashes between all tables except for DNS tables
	tables := []string{"conn", "http", "ssl", "uconn", "usni"}
	for _, table := range tables {
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": table,
		})
		var count uint64
		err = it.db.Conn.QueryRow(ctx, `--sql
		SELECT count() FROM (
			SELECT DISTINCT hex(hash) FROM {table:Identifier} c
			INNER JOIN {table:Identifier} cc ON c.hash = cc.hash AND cc.src_nuid = '779a5281-949d-4ae3-9de4-309c955f48c0'
			WHERE c.src_nuid = '439264be-a146-4759-80f7-f4fb23b9b346' 
		)
	`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "there should be no overlapping hashes in the %s table", table)
	}

}

func (it *NetworkIDSuite) TestFQDNOnly() {
	t := it.T()

	// make sure that no SNI or C2 over DNS connections in the mixtape have a dst_nuid
	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `--sql
			SELECT count() FROM threat_mixtape
			WHERE fqdn != '' AND dst_nuid != '00000000-0000-0000-0000-000000000000' 
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no connections with a FQDN that have a dst_nuid filled out")

	// make sure that the dst_nuid is filled out for all connections with no FQDN
	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
			SELECT count() FROM threat_mixtape
			WHERE fqdn = '' AND dst_nuid = '00000000-0000-0000-0000-000000000000' 
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no connections without a FQDN that have an empty/zero dst_nuid")

	// make sure that the beacon type is ip for all connections when the dst_nuid is filled out and there's no FQDN
	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
			SELECT count() FROM threat_mixtape
			WHERE fqdn = '' AND dst_nuid != '00000000-0000-0000-0000-000000000000' AND modifier_name = ''
			AND beacon_type != 'ip'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no IP connections that are not marked as ip beacons")

	// verify that the beacon type for SNI connections matches expected FQDN/dst_nuid combination
	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
			SELECT count() FROM threat_mixtape
			WHERE src != '::' AND fqdn != '' AND dst_nuid = '00000000-0000-0000-0000-000000000000' AND modifier_name = ''
			AND beacon_type != 'sni'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no SNI connections that aren't marked as a sni beacon")

	// verify that the beacon type for C2 over DNS connections matches expected FQDN/dst_nuid combination
	err = it.db.Conn.QueryRow(it.db.GetContext(), `--sql
			SELECT count() FROM threat_mixtape
			WHERE src = '::' AND fqdn != '' AND dst_nuid = '00000000-0000-0000-0000-000000000000' AND modifier_name = ''
			AND beacon_type != 'dns'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "there should be no C2 over DNS connections that aren't marked as a dns 'beacon'")

}

func (it *NetworkIDSuite) TestExternalHosts() {
	// - all dst that arent local should have the default external id
	// - src should only have default external id if its not local (according to RFC 1918, since those are publicly routable)
	t := it.T()

	tables := []string{"conn", "http", "ssl", "uconn", "usni"}

	for _, table := range tables {
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": table,
		})
		var count uint64
		err := it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {table:Identifier}
			WHERE dst_local = false AND dst_nuid != 'ffffffff-ffff-ffff-ffff-ffffffffffff'
		`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "table: %s, the default external nuid should be used if the dst IP is external", table)

		err = it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {table:Identifier}
			WHERE src_local = false AND src_nuid != 'ffffffff-ffff-ffff-ffff-ffffffffffff'
		`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "table: %s, the default external nuid should be used if the src IP is external", table)

		err = it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {table:Identifier}
			WHERE src_local = true AND src_nuid = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
		`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "table: %s, the default external nuid should not be used if the src IP is internal (according to RFC 1918)", table)
	}

}

// TestDefaultNetworkID is ran in the ValidDatasetTestSuite since the valid dataset does not have custom agent UUIDs,
// so every UUID is either the default internal or default external UUID
func (it *ValidDatasetTestSuite) TestDefaultNetworkID() {
	t := it.T()

	// - all internal src IPs should use default local src_nuid
	tables := []string{"conn", "http", "ssl", "uconn", "usni"}

	for _, table := range tables {
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": table,
		})
		var count uint64
		err := it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {table:Identifier}
			WHERE src_local = true AND src_nuid != 'ffffffff-ffff-ffff-ffff-fffffffffffe'
		`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "table: %s, the default internal nuid should be used if the src IP is internal", table)

		err = it.db.Conn.QueryRow(ctx, `--sql
			SELECT count() FROM {table:Identifier}
			WHERE dst_local = true AND dst_nuid != 'ffffffff-ffff-ffff-ffff-fffffffffffe'
		`).Scan(&count)
		require.NoError(t, err)
		require.EqualValues(t, 0, count, "table: %s, the default internal nuid should be used if the dst IP is internal", table)
	}

	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `--sql
		SELECT count() FROM (
			SELECT DISTINCT hash, src_nuid FROM conn
			WHERE src = '10.55.200.10' AND dst = '205.251.197.234'
		)
	`).Scan(&count)
	require.NoError(t, err, "retrieving the counts for overlapping IPs should not error")
	require.EqualValues(t, 1, count, "overlapping IP from agent dataset should have a single hash and src_nuid in this dataset")

}
