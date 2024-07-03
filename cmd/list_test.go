package cmd_test

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/activecm/rita/cmd"
	"github.com/activecm/rita/config"
	"github.com/activecm/rita/database"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func (c *CmdTestSuite) TestFormatListTable() {
	require := require.New(c.T())

	_, err := cmd.RunImportCmd(time.Now(), c.cfg, afero.NewOsFs(), "../test_data/valid_tsv", "dnscat", false, true)
	require.NoError(err, "importing dnscat data should not produce an error")

	_, err = cmd.RunImportCmd(time.Now(), c.cfg, afero.NewOsFs(), "../test_data/proxy", "proxy", false, true)
	require.NoError(err, "importing proxy data should not produce an error")

	_, dropletSubnet, err := net.ParseCIDR("64.225.56.201/32")
	require.NoError(err)
	c.cfg.Filter.InternalSubnets = append(c.cfg.Filter.InternalSubnets, dropletSubnet)
	c.cfg.Filter.FilterExternalToInternal = false
	err = config.UpdateConfig(c.cfg)
	require.NoError(err, "config should update without error")

	_, err = cmd.RunImportCmd(time.Now(), c.cfg, afero.NewOsFs(), "../test_data/missing_host/2024-04-19", "fake_rolling", true, true)
	require.NoError(err, "importing fake_rolling data should not produce an error")

	_, err = cmd.RunImportCmd(time.Now(), c.cfg, afero.NewOsFs(), "../test_data/missing_host/2024-04-20", "fake_rolling", true, false)
	require.NoError(err, "importing 2nd fake_rolling data should not produce an error")

	// connect to server
	server, err := database.ConnectToServer(context.Background(), c.cfg)
	require.NoError(err)

	dbs, err := server.ListImportDatabases()
	require.NoError(err)

	output := cmd.FormatListTable(dbs)

	lines := strings.Split(output.String(), "\n")
	require.Len(lines, 7)
	lines = lines[3:6]

	expectedDBs := []struct {
		name    string
		rolling string
		tsRange string
	}{
		{name: "fake_rolling", rolling: "true", tsRange: "2024-04-18 20:07 - 2024-04-20 23:59"},
		{name: "proxy", rolling: "false", tsRange: "2022-12-22 18:48 - 2023-01-05 18:48"},
		{name: "dnscat", rolling: "false", tsRange: "2018-01-30 18:00 - 2018-01-31 18:14"},
	}
	for i, line := range lines {
		cols := strings.Split(line, "│")
		require.Len(cols, 5)
		cols = cols[1:4]
		require.Equal(expectedDBs[i].name, strings.TrimSpace(cols[0]))
		require.Equal(expectedDBs[i].rolling, strings.TrimSpace(cols[1]))
		require.Equal(expectedDBs[i].tsRange, strings.TrimSpace(cols[2]))
	}
}
