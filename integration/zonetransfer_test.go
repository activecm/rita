package integration_test

import (
	"context"
	"testing"

	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/zonetransfer"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ZoneTransferSuite FilterTestSuite

func TestZoneTransfer(t *testing.T) {
	suite.Run(t, new(ZoneTransferSuite))

}

// Reset config after each test since these tests load the config from a file
func (it *ZoneTransferSuite) SetupSuite() {
	t := it.T()
	afs := afero.NewOsFs()
	cfg, err := config.ReadFileConfig(afs, ConfigPath)
	require.NoError(t, err)
	cfg.Env.DBConnection = dockerInfo.clickhouseConnection
	it.cfg = cfg

	db, err := database.ConnectToServer(context.Background(), it.cfg)
	require.NoError(t, err)
	require.NoError(t, db.Conn.Exec(db.GetContext(), "TRUNCATE TABLE metadatabase.performed_zone_transfers"))

}

func (it *ZoneTransferSuite) SetupTest() {
	err := it.cfg.Reset()
	it.Require().NoError(err)
}

func (it *ZoneTransferSuite) TearDownSuite() {
	err := it.cfg.Reset()
	it.Require().NoError(err)
}

func (it *ZoneTransferSuite) TestRecordZoneTransferPerformed() {
	t := it.T()

	it.cfg.ZoneTransfer.Enabled = true
	it.cfg.ZoneTransfer.DomainName = "bug.corp."
	it.cfg.ZoneTransfer.NameServer = "dc1.bug.corp:53"

	// connect to database
	db, err := database.ConnectToServer(context.Background(), it.cfg)
	require.NoError(t, err)

	tests := []struct {
		label         string
		toCreate      zonetransfer.PerformedZoneTransfer
		changeConfig  bool
		expectedIndex int
	}{
		{
			label: "First entry should return itself",
			toCreate: zonetransfer.PerformedZoneTransfer{
				PerformedAt: time.Unix(1515531081, 0).UTC(),
				DomainName:  "bug.corp.",
				NameServer:  "dc1.bug.corp:53",
				Serial:      100,
				MBox:        "example@bug.corp",
			},
			expectedIndex: 0,
		},

		{
			label: "Newer timestamp should return itself",
			toCreate: zonetransfer.PerformedZoneTransfer{
				PerformedAt: time.Unix(1615531081, 0).UTC(),
				DomainName:  "bug.corp.",
				NameServer:  "dc1.bug.corp:53",
				Serial:      100,
				MBox:        "example@bug.corp",
			},
			expectedIndex: 1,
		},
		{
			label: "Older timestamp shouldn't return itself",
			toCreate: zonetransfer.PerformedZoneTransfer{
				PerformedAt: time.Unix(1415531081, 0).UTC(),
				DomainName:  "bug.corp.",
				NameServer:  "dc1.bug.corp:53",
				Serial:      100,
				MBox:        "example@bug.corp",
			},
			expectedIndex: 1,
		},
		{
			label:        "It should filter by domain name and name server",
			changeConfig: true,
			toCreate: zonetransfer.PerformedZoneTransfer{
				PerformedAt: time.Unix(1415531081, 0).UTC(),
				DomainName:  "bug2.corp2.",
				NameServer:  "dc1.bug2.corp2:53",
				Serial:      100,
				MBox:        "example@bug.corp",
			},
			expectedIndex: 3,
		},
	}

	zt, err := zonetransfer.NewZoneTransfer(db, it.cfg)
	require.NoError(t, err)
	// there should be no error if no zone transfer was performed yet, but result should be nil
	latestZT, err := zt.FindLastZoneTransfer()
	require.NoError(t, err)
	require.Nil(t, latestZT)

	for _, tc := range tests {
		// switch to a different domain/name server for this
		if tc.changeConfig {
			it.cfg.ZoneTransfer.DomainName = tc.toCreate.DomainName
			it.cfg.ZoneTransfer.NameServer = tc.toCreate.NameServer
		}
		zt, err := zonetransfer.NewZoneTransfer(db, it.cfg)
		require.NoError(t, err)

		zt.SetTransferInfo(tc.toCreate)
		require.NoError(t, zt.RecordZoneTransferPerformed(), "recording zone transfer shouldn't fail: %s", tc.label)

		latestZT, err := zt.FindLastZoneTransfer()
		require.NoError(t, err)
		require.NotNil(t, latestZT)

		require.Equal(t, tests[tc.expectedIndex].toCreate, *latestZT, "latest zone transfer found should match expected performed zone transfer: %s", tc.label)
	}
}
