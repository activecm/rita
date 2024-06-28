package cmd

import (
	"errors"

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
