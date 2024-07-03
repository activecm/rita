package cmd

import (
	"errors"
	"fmt"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/util"

	"github.com/google/go-github/github"
	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ErrMissingDatabaseName = errors.New("database name is required")
var ErrMissingConfigPath = errors.New("config path parameter is required")
var ErrTooManyArguments = errors.New("too many arguments provided")

func Commands() []*cli.Command {
	return []*cli.Command{
		ImportCommand,
		ViewCommand,
		DeleteCommand,
		ListCommand,
		ValidateConfigCommand,
	}
}

func ConfigFlag(required bool) *cli.StringFlag {
	return &cli.StringFlag{
		Name:     "config",
		Aliases:  []string{"c"},
		Usage:    "Load configuration from `FILE`",
		Value:    "./config.hjson", // default config file path
		Required: required,
		Action: func(_ *cli.Context, path string) error {
			return ValidateConfigPath(afero.NewOsFs(), path)
		},
	}
}

func CheckForUpdate(cCtx *cli.Context, afs afero.Fs) error {
	// get the current version
	currentVersion := config.Version

	// load config file
	cfg, err := config.LoadConfig(afs, cCtx.String("config"))
	if err != nil {
		return fmt.Errorf("error loading config file: %w", err)
	}

	// check for update if version is set
	if cfg.UpdateCheckEnabled && currentVersion != "" {
		newer, latestVersion, err := util.CheckForNewerVersion(github.NewClient(nil), currentVersion)
		if err != nil {
			return fmt.Errorf("error checking for newer version of RITA: %w", err)
		}
		if newer {
			fmt.Printf("\n\t✨ A newer version (%s) of RITA is available! https://github.com/activecm/rita/releases ✨\n\n", latestVersion)
		}
	}
	return nil
}
