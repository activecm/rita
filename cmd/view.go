package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/util"
	"github.com/activecm/rita/v5/viewer"

	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ErrMissingSearchValue = errors.New("search value cannot be empty")
var ErrMissingSearchStdout = errors.New("cannot apply search without --stdout")
var ErrMissingLimitStdout = errors.New("cannot apply limit without --stdout")
var ErrInvalidViewLimit = errors.New("limit must be a positive interger greater than 0")
var ErrDatabaseNotFound = errors.New("database not found")

var ViewCommand = &cli.Command{
	Name:  "view",
	Usage: "view <dataset name>",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:     "stdout",
			Aliases:  []string{"o"},
			Usage:    "pipe comma-delimited data to stdout",
			Required: false,
		},
		&cli.StringFlag{
			Name:     "search",
			Aliases:  []string{"s"},
			Usage:    `search criteria to apply to results piped to stdout, only works with --stdout/-o flag, format: -s="field:value, field:value, ..."`,
			Required: false,
		},
		&cli.IntFlag{
			Name:     "limit",
			Aliases:  []string{"l"},
			Usage:    "limit the number of results to display",
			Required: false,
		},
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {
		// flags must go before the argument, otherwise they won't be applied ._.
		// we can either make the db name a flag or see if cobra is any better
		if !cCtx.Args().Present() {
			return ErrMissingDatabaseName
		}

		if err := ValidateDatabaseName(cCtx.Args().First()); err != nil {
			return err
		}

		if cCtx.IsSet("search") {
			if !cCtx.Bool("stdout") {
				return ErrMissingSearchStdout
			}

			if cCtx.String("search") == "" {
				return ErrMissingSearchValue
			}
		}

		// validate limit flag
		if cCtx.IsSet("limit") {
			if !cCtx.Bool("stdout") {
				return ErrMissingLimitStdout
			}

			if cCtx.Int("limit") <= 0 {
				return ErrInvalidViewLimit
			}
		}

		// set up file system interface
		afs := afero.NewOsFs()

		// load config file
		cfg, err := config.ReadFileConfig(afs, cCtx.String("config"))
		if err != nil {
			return err
		}

		// run the view command
		if err := runViewCmd(cfg, cCtx.Args().First(), cCtx.Bool("stdout"), cCtx.String("search"), cCtx.Int("limit")); err != nil {
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cfg); err != nil {
			return err
		}

		return nil
	},
}

func runViewCmd(cfg *config.Config, dbName string, stdout bool, search string, limit int) error {
	fmt.Printf("Viewing database: %s\n", dbName)

	// connect to database
	db, err := database.ConnectToDB(context.Background(), dbName, cfg, nil)
	if err != nil {
		return err
	}

	// determine which max timestamp to use for relative time calculations
	minTimestamp, maxTimestamp, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDatabaseNotFound
		}
		return err
	}

	// if stdout was requested, get CSV output
	if stdout {

		// get CSV output
		csvData, err := viewer.GetCSVOutput(db, minTimestamp, util.GetRelativeFirstSeenTimestamp(useCurrentTime, maxTimestamp), search, limit)
		if err != nil {
			return err
		}

		// print CSV data to stdout
		fmt.Println(csvData)

	} else {

		// create UI
		if err := viewer.CreateUI(cfg, db, useCurrentTime, maxTimestamp, minTimestamp); err != nil {
			return err
		}
	}

	return nil
}
