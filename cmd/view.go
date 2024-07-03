package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/activecm/rita/config"
	"github.com/activecm/rita/database"
	"github.com/activecm/rita/util"
	"github.com/activecm/rita/viewer"

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
	},
	Action: func(cCtx *cli.Context) error {
		afs := afero.NewOsFs()

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

		if err := runViewCmd(afs, cCtx.String("config"), cCtx.Args().First(), cCtx.Bool("stdout"), cCtx.String("search"), cCtx.Int("limit")); err != nil {
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cCtx, afero.NewOsFs()); err != nil {
			return err
		}

		return nil
	},
}

func runViewCmd(afs afero.Fs, configPath string, dbName string, stdout bool, search string, limit int) error {
	fmt.Printf("Viewing database: %s\n", dbName)

	// load config file
	cfg, err := config.LoadConfig(afs, configPath)
	if err != nil {
		return err
	}

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

// func validateDatabaseName(dbName string) error {
// 	//  do not allow anything but alphanumeric and underscores for the database name
// 	re := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// 	if !re.MatchString(dbName) {
// 		return fmt.Errorf("invalid database name: %s", dbName)
// 	}

// 	return nil
// }
