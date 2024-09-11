package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/activecm/rita/v5/analysis"
	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/progressbar"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/errgroup"
)

type FilterTestSuite struct {
	suite.Suite
	cfg *config.Config
}

func TestFilters(t *testing.T) {
	suite.Run(t, new(FilterTestSuite))
}

// Reset config after each test since these tests load the config from a file
func (it *FilterTestSuite) SetupSuite() {
	t := it.T()
	afs := afero.NewOsFs()
	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)
	it.cfg = cfg
}

func (it *FilterTestSuite) SetupTest() {
	t := it.T()
	err := it.cfg.Reset()
	require.NoError(t, err)
}

func (it *FilterTestSuite) TearDownSuite() {
	t := it.T()
	err := it.cfg.Reset()
	require.NoError(t, err)
}

func (it *FilterTestSuite) TestNeverIncludeSubnets() {
	t := it.T()
	// set up file system interface
	afs := afero.NewMemMapFs()
	afs2 := afero.NewOsFs()
	err := afero.WriteFile(afs, "testsuite_config.hjson", []byte(`
	{
		filtering: {
			filter_external_to_internal: true,
			internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
			never_included_subnets: ["10.55.100.0/24"],
		},
		threat_intel: {
			online_feeds: ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
			custom_feeds_directory: "./deployment/threat_intel_feeds"
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.ReadFileConfig(afs, "testsuite_config.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	it.cfg = cfg
	require.Contains(t, cfg.Filtering.NeverIncludedSubnets, &net.IPNet{IP: net.IP{10, 55, 100, 0}, Mask: net.IPMask{255, 255, 255, 0}})

	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs2, "../test_data/valid_tsv", "never_include_subnet", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "never_include_subnet", cfg, nil)
	require.NoError(t, err)

	var count uint64

	// verify that not all connections in 10.0.0.0/8 were filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM conn
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 14452-12584, count, "conn table should contain 1868 entries in 10.0.0.0/8, got: %d", count)

	// 5531 in 10.55.100.0/24
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM ssl
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 5615-(5531), count, "ssl table should contain 63 entries in 10.0.0.0/8, got: %d", count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM http
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 2004-(1982), count, "http table should contain 22 entries in 10.0.0.0/8, got: %d", count)

	// verify that all connections in 10.55.100.0/24 were filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM conn
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "conn table shouldn't contain any entries in 10.55.100.0/24")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "http table shouldn't contain any entries in 10.55.100.0/24")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "ssl table shouldn't contain any entries in 10.55.100.0/24")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "dns table shouldn't contain any entries in 10.55.100.0/24")

}

func (it *FilterTestSuite) TestNeverIncludeDomains() {
	t := it.T()
	// set up file system interface
	afs := afero.NewMemMapFs()
	afs2 := afero.NewOsFs()
	err := afero.WriteFile(afs, "testsuite_config2.hjson", []byte(`
	{
		filtering: {
			filter_external_to_internal: true,
			internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
			never_included_domains: ["*.microsoft.com", "businessinsider.com"]
		},
		threat_intel: {
			online_feeds: ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
			custom_feeds_directory: "./deployment/threat_intel_feeds"
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.ReadFileConfig(afs, "testsuite_config2.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	it.cfg = cfg

	require.Contains(t, cfg.Filtering.NeverIncludedDomains, "*.microsoft.com")
	require.Contains(t, cfg.Filtering.NeverIncludedDomains, "businessinsider.com")

	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs2, "../test_data/valid_tsv", "never_include_domain", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "never_include_domain", cfg, nil)
	require.NoError(t, err)

	var count uint64

	// verify that all connections w/ fqdns ending in .microsoft.com are filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE cutToFirstSignificantSubdomain(host) = 'microsoft.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "http table shouldn't contain any entries with host ending in .microsoft.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE cutToFirstSignificantSubdomain(server_name) = 'microsoft.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "ssl table shouldn't contain any entries with server_name ending in .microsoft.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE cutToFirstSignificantSubdomain(query) = 'microsoft.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "dns table shouldn't contain any entries with query ending in .microsoft.com")

	// verify that not all domains in .businessinsider.com are filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE cutToFirstSignificantSubdomain(query) = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "dns table should contain at least one entry with a query ending in .businessinsider.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE cutToFirstSignificantSubdomain(host) = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "http table should contain at least one entry with a host ending in .businessinsider.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE cutToFirstSignificantSubdomain(server_name) = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "ssl table should contain at least one entry with a server_name ending in .businessinsider.com")

	// verify that businessinsider.com is filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE query = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "dns table shouldn't contain any entries with a query of .businessinsider.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE host = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "http table shouldn't contain any entries with a query of .businessinsider.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE server_name = 'businessinsider.com'
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "ssl table shouldn't contain any entries with a query of .businessinsider.com")

}

func (it *FilterTestSuite) TestAlwaysIncludeSubnets() {
	t := it.T()
	// set up file system interface
	afs := afero.NewMemMapFs()
	afs2 := afero.NewOsFs()
	err := afero.WriteFile(afs, "testsuite_config3.hjson", []byte(`
	{
		filtering: {
			filter_external_to_internal: true,
			internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
			never_included_subnets: ["10.0.0.0/8"],
			always_included_subnets: ["10.55.100.0/24"]
		},
		threat_intel: {
			online_feeds: ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
			custom_feeds_directory: "./deployment/threat_intel_feeds"
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.ReadFileConfig(afs, "testsuite_config3.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	it.cfg = cfg

	require.Contains(t, cfg.Filtering.NeverIncludedSubnets, &net.IPNet{IP: net.IP{10, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}, "never included subnets should contain 10.0.0.0/8")
	require.Contains(t, cfg.Filtering.AlwaysIncludedSubnets, &net.IPNet{IP: net.IP{10, 55, 100, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "always included subnets should contain 10.55.100.0/24")

	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs2, "../test_data/valid_tsv", "always_include_subnet", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "always_include_subnet", cfg, nil)
	require.NoError(t, err)

	var count uint64

	// verify that not all connections in 10.0.0.0/8 were filtered
	conn := 12591
	http := 1982
	ssl := 5531

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM conn
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, conn, count, "conn table should contain %d entries in 10.0.0.0/8, got: %d", conn, count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM ssl
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, ssl, count, "ssl table should contain %d entries in 10.0.0.0/8, got: %d", ssl, count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM http
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.0.0.0/104') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.0.0.0/104')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, http, count, "http table should contain %d entries in 10.0.0.0/8, got: %d", http, count)

	// verify that all connections in 10.55.100.0/24 were filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM conn
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, conn, count, "conn table shouldn contain %d any entries in 10.55.100.0/24, got: %d", conn, count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM http
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, http, count, "http table shouldn contain %d entries in 10.55.100.0/24, got: %d", http, count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM ssl
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, ssl, count, "ssl table should contain %d entries in 10.55.100.0/24", ssl, count)

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count(DISTINCT hash) FROM dns
		WHERE isIPAddressInRange(IPv6NumToString(src), '::ffff:10.55.100.0/120') OR isIPAddressInRange(IPv6NumToString(dst), '::ffff:10.55.100.0/120')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "dns table should contain 1 entry in 10.55.100.0/24")

}

func (it *FilterTestSuite) TestAlwaysIncludeDomains() {
	t := it.T()
	// set up file system interface
	afs := afero.NewMemMapFs()
	afs2 := afero.NewOsFs()
	err := afero.WriteFile(afs, "testsuite_config4.hjson", []byte(`
	{
		filtering: {
			filter_external_to_internal: true,
			internal_subnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
			never_included_domains: ["*.microsoft.com", "businessinsider.com"],
			always_included_domains: ["*.mp.microsoft.com", "analytics.businessinsider.com"]
		},
		threat_intel: {
			online_feeds: ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
			custom_feeds_directory: "./deployment/threat_intel_feeds"
		},
		http_extensions_file_path: "../deployment/http_extensions_list.csv"
	}
	`), 0755)
	require.NoError(t, err)

	cfg, err := config.ReadFileConfig(afs, "testsuite_config4.hjson")
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	it.cfg = cfg

	require.Contains(t, cfg.Filtering.NeverIncludedDomains, "*.microsoft.com")
	require.Contains(t, cfg.Filtering.NeverIncludedDomains, "businessinsider.com")

	require.Contains(t, cfg.Filtering.AlwaysIncludedDomains, "*.mp.microsoft.com")
	require.Contains(t, cfg.Filtering.AlwaysIncludedDomains, "analytics.businessinsider.com")

	// // import data
	_, err = cmd.RunImportCmd(time.Now(), cfg, afs2, "../test_data/valid_tsv", "always_include_domain", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "always_include_domain", cfg, nil)
	require.NoError(t, err)

	var count uint64

	// verify that all connections w/ fqdns ending in .microsoft.com (but not *.mp.microsoft.com) are filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE cutToFirstSignificantSubdomain(host) = 'microsoft.com' AND NOT endsWith(host, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "http table shouldn't contain any entries with host ending in .microsoft.com (but not *.mp.microsoft.com)")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE cutToFirstSignificantSubdomain(server_name) = 'microsoft.com' AND NOT endsWith(server_name, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "ssl table shouldn't contain any entries with server_name ending in .microsoft.com (but not *.mp.microsoft.com)")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE cutToFirstSignificantSubdomain(query) = 'microsoft.com' AND NOT endsWith(query, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 0, count, "dns table shouldn't contain any entries with query ending in .microsoft.com (but not *.mp.microsoft.com)")

	// verify that connections w/ fqdns ending in *.mp.microsoft.com are not filtered
	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM http
		WHERE endsWith(host, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "http table should contain at least 1 entry with host ending in .mp.microsoft.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM ssl
		WHERE endsWith(server_name, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "ssl table should contain at least 1 entry with server name ending in .microsoft.com")

	err = db.Conn.QueryRow(db.GetContext(), `
		SELECT count() FROM dns
		WHERE endsWith(query, '.mp.microsoft.com')
	`).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, uint64(0), "dns table should contain at least 1 entry with query ending in .microsoft.com")

	tables := []struct {
		name  string
		field string
	}{{name: "dns", field: "query"}, {name: "http", field: "host"}, {name: "ssl", field: "server_name"}}

	domains := []struct {
		d                string
		shouldBeFiltered bool
	}{{d: "businessinsider.com", shouldBeFiltered: true}, {d: "static2.businessinsider.com", shouldBeFiltered: false}}

	for _, domain := range domains {
		for _, table := range tables {
			chCtx := db.QueryParameters(clickhouse.Parameters{
				"table":  table.name,
				"field":  table.field,
				"domain": domain.d,
			})

			// verify that not all subdomains in this domain are filtered (wildcard shouldn't apply)
			err = db.Conn.QueryRow(chCtx, `
				SELECT count() FROM {table:Identifier}
				WHERE endsWith({field:Identifier}, {domain:String})
			`).Scan(&count)
			require.NoError(t, err)
			require.Greater(t, count, uint64(0), "%s table should contain at least one entry with a domain that ends in .%s", table.name, domain.d)

			// verify that domain is filtered (if it should be)
			err = db.Conn.QueryRow(chCtx, `
				SELECT count() FROM {table:Identifier}
				WHERE {field:Identifier} = {domain:String}
			`).Scan(&count)
			require.NoError(t, err)
			if domain.shouldBeFiltered {
				require.EqualValues(t, 0, count, "%s table shouldn't contain any entries with a domain of %s", table, domain.d)
			} else {
				require.Greater(t, count, uint64(0), "%s table should contain at least one entry with a domain of %s", table.name, domain.d)
			}

		}
	}
}

// TestFilterExternalToInternal also tests ICMP
func (it *FilterTestSuite) TestFilterExternalToInternal() {
	t := it.T()
	// set up file system interface
	afs := afero.NewOsFs()

	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	cfg.Filtering.FilterExternalToInternal = false
	it.cfg = cfg
	require.NoError(t, err, "updating config should not return an error")

	require.False(t, cfg.Filtering.FilterExternalToInternal)

	// // import data
	importResults, err := cmd.RunImportCmd(time.Now(), cfg, afs, "../test_data/valid_tsv", "filter_ext_to_int", false, true)
	require.NoError(t, err)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), "filter_ext_to_int", cfg, nil)
	require.NoError(t, err)

	// 	// there are ICMP connections that are only on connections that are external to internal

	type protoInfo struct {
		PortProtoService string `ch:"port_proto_service"`
		ConnCount        uint64 `ch:"conn_count"`
		BytesSent        int64  `ch:"bytes_sent"`
		BytesReceived    int64  `ch:"bytes_received"`
	}

	type testData struct {
		src          string
		dst          string
		portInfoList []protoInfo
	}

	testCases := []testData{
		{
			src: "165.227.88.15",
			dst: "192.168.88.2",
			portInfoList: []protoInfo{
				{"icmp:3/3", 2, 4858, 0},
			},
		},
		{
			src: "66.218.84.141",
			dst: "10.55.100.107",
			portInfoList: []protoInfo{
				{"icmp:3/3", 1, 240, 0},
			},
		},
		{
			src: "66.218.84.141",
			dst: "10.55.100.104",
			portInfoList: []protoInfo{
				{"icmp:3/3", 1, 240, 0},
			},
		},
		{
			src: "66.218.84.141",
			dst: "10.55.100.108",
			portInfoList: []protoInfo{
				{"icmp:3/3", 1, 240, 0},
			},
		},
		{
			src: "67.226.210.13",
			dst: "10.55.100.106",
			portInfoList: []protoInfo{
				{"icmp:3/10", 1, 136, 0},
			},
		},
		{
			src: "67.226.210.15",
			dst: "10.55.100.107",
			portInfoList: []protoInfo{
				{"icmp:3/10", 1, 136, 0},
			},
		},
		{
			src: "67.226.210.14",
			dst: "10.55.100.108",
			portInfoList: []protoInfo{
				{"icmp:3/10", 1, 136, 0},
			},
		},
		{
			src: "24.220.6.168",
			dst: "10.55.200.11",
			portInfoList: []protoInfo{
				{"icmp:3/13", 1, 96, 0},
			},
		},
	}

	for _, test := range testCases {
		ctx := clickhouse.Context(context.Background(), clickhouse.WithParameters(clickhouse.Parameters{
			"src": test.src,
			"dst": test.dst,
		}))

		var res []protoInfo
		err = db.Conn.Select(ctx, &res, `
			SELECT concat(proto, ':', icmp_type, '/', icmp_code) AS port_proto_service,
				countMerge(count) AS conn_count,
				sumMerge(bytes_sent) AS bytes_sent,
				sumMerge(bytes_received) AS bytes_received
			FROM port_info
			WHERE src={src:String} AND dst={dst:String}
			GROUP BY src, dst, dst_port, proto, service, icmp_type, icmp_code
		`)
		require.NoError(t, err, "querying proto table should not produce an error")

		// ensure that the length of the result list matches the expected value
		require.Len(t, res, len(test.portInfoList), "length of result list should match expected value")

		// ensure that the result list matches the expected value
		require.ElementsMatch(t, test.portInfoList, res, "result list should match expected value")
	}

	/* ******* Mixtape Propagation *******
	The entries that use ICMP don't have enough connections to qualify as beacons, so they don't appear in the mixtape.
	In order to test the spagooper query that grabs the ICMP entries within port:proto:service, we have to go through
	the results of the IP spagooper.
	*/

	// set up new analyzer
	minTSBeacon, maxTSBeacon, notFromConn, err := db.GetBeaconMinMaxTimestamps()
	require.NoError(t, err)
	require.False(t, notFromConn, "min and max timestamps should be from conn table")

	minTS, maxTS, notFromConn, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
	require.NoError(t, err)
	require.False(t, notFromConn, "min and max timestamps should be from conn table")
	require.False(t, useCurrentTime, "first seen analysis should not use the current time")

	analyzer, err := analysis.NewAnalyzer(db, cfg, importResults.ImportID[0], minTS, maxTS, minTSBeacon, maxTSBeacon, useCurrentTime, false)
	require.NoError(t, err)

	ctx := context.Background()
	queryGroup, ctx := errgroup.WithContext(ctx)

	// create progress bars
	bars := progressbar.New(ctx, []*progressbar.ProgressBar{
		progressbar.NewBar("IP Connection Analysis ", 2, progress.New(progress.WithDefaultGradient())),
	}, []progressbar.Spinner{})

	type foundEntry struct {
		PortProtoService string
		ConnCount        uint64
		TotalBytes       int64
	}
	type resData struct {
		src          string
		dst          string
		portInfoList []foundEntry
	}
	var foundIPs []resData

	var expectedResData []resData

	for _, test := range testCases {
		d := resData{
			src: test.src,
			dst: test.dst,
		}
		var p []foundEntry
		for _, dd := range test.portInfoList {
			p = append(p, foundEntry{
				PortProtoService: dd.PortProtoService,
				ConnCount:        dd.ConnCount,
				TotalBytes:       (dd.BytesSent + dd.BytesReceived) * 2, // multiply by 2 for openconns
			})
		}
		d.portInfoList = p
		expectedResData = append(expectedResData, d)
	}

	queryGroup.Go(func() error {
		for entry := range analyzer.UconnChan {

			for _, test := range testCases {
				if entry.Src.String() == test.src && entry.Dst.String() == test.dst {
					f := resData{
						src: entry.Src.String(),
						dst: entry.Dst.String(),
					}
					var portProto []foundEntry
					for _, p := range entry.PortProtoService {
						port := foundEntry{
							PortProtoService: p,
							ConnCount:        entry.Count,
							TotalBytes:       entry.TotalBytes,
						}
						portProto = append(portProto, port)
					}
					f.portInfoList = portProto
					foundIPs = append(foundIPs, f)
				}
			}

		}
		return nil
	})

	queryGroup.Go(func() error {
		err := analyzer.ScoopIPConns(ctx, bars)
		require.NoError(t, err)
		close(analyzer.UconnChan)
		return err
	})

	queryGroup.Go(func() error {
		_, err := bars.Run()
		require.NoError(t, err)
		return err
	})

	if err := queryGroup.Wait(); err != nil {

		require.NoError(t, err)
	}

	require.ElementsMatch(t, expectedResData, foundIPs)
}
