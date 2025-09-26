package cmd

import (
	"context"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/zonetransfer"
	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ZoneTransferCommand = &cli.Command{
	Name:        "zone-transfer",
	Usage:       "perform a zone transfer on the configured domain",
	UsageText:   "zone-transfer",
	Description: "performs a zone transfer on the configured domain",
	Args:        false,
	Flags: []cli.Flag{
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {

		// check if too many arguments were provided
		if cCtx.NArg() > 0 {
			return ErrTooManyArguments
		}

		// set up file system interface
		afs := afero.NewOsFs()

		// load config file
		cfg, err := config.ReadFileConfig(afs, cCtx.String("config"))
		if err != nil {
			return err
		}

		// run the delete command
		if err := runZoneTransferCmd(cfg); err != nil {
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cfg); err != nil {
			return err
		}

		return nil
	},
}

func runZoneTransferCmd(cfg *config.Config) error {

	// connect to server
	server, err := database.ConnectToServer(context.Background(), cfg)
	if err != nil {
		return err
	}

	// create tables if they don't already exist
	if err := server.CreateServerDBTables(); err != nil {
		return err
	}

	zt, err := zonetransfer.NewZoneTransfer(server, cfg)
	if err != nil {
		return err
	}

	if err := zt.PerformZoneTransfer(); err != nil {
		return err
	}
	return nil
}
