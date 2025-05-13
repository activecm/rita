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
var ErrInvalidConfigObject = errors.New("config was nil or invalid")
var ErrCurrentVersionEmpty = errors.New("current version unset")
var ErrCheckingForUpdate = errors.New("error checking for newer version of RITA")

func Commands() []*cli.Command {
	return []*cli.Command{
		ImportCommand,
		ViewCommand,
		DeleteCommand,
		ListCommand,
		ValidateConfigCommand,
		ZoneTransferCommand,
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

func CheckForUpdate(cfg *config.Config) error {
	// make sure config is not nil
	if cfg == nil {
		return ErrInvalidConfigObject
	}

	// get the current version
	currentVersion := config.Version

	// check for update if version is set
	if cfg.RITA.UpdateCheckEnabled && currentVersion != "" && currentVersion != "dev" {
		newer, latestVersion, err := util.CheckForNewerVersion(github.NewClient(nil), currentVersion)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCheckingForUpdate, err)
		}
		if newer {
			fmt.Printf("\n\t✨ A newer version (%s) of RITA is available! https://github.com/activecm/rita/releases ✨\n\n", latestVersion)
		}
	}
	return nil
}
