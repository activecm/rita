package cmd

import (
	"errors"
	"fmt"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/util"

	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ErrInvalidConfig = errors.New("encountered invalid configuration values")

var ValidateConfigCommand = &cli.Command{
	Name:      "validate",
	Usage:     "validate a configuration file",
	UsageText: "validate [--config FILE]",
	Args:      false,
	Flags: []cli.Flag{
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {
		// check if a config was provided and is not empty
		if cCtx.String("config") == "" {
			return ErrMissingConfigPath
		}

		// check if too many arguments were provided
		if cCtx.NArg() > 0 {
			return ErrTooManyArguments
		}

		afs := afero.NewOsFs()

		// validate config file
		cfg, err := RunValidateConfigCommand(afs, cCtx.String("config"))
		if err != nil {
			fmt.Printf("\n\t[!] Configuration file is not valid...")
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cfg); err != nil {
			return err
		}

		return nil
	},
}

func RunValidateConfigCommand(afs afero.Fs, configPath string) (*config.Config, error) {
	// validate config file path
	if err := ValidateConfigPath(afs, configPath); err != nil {
		return nil, err
	}

	// load config path
	cfg, err := config.ReadFileConfig(afs, configPath)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n\t[✨] Configuration file is valid \n\n")

	return cfg, nil
}

func ValidateConfigPath(afs afero.Fs, configPath string) error {
	if configPath == "" {
		return ErrMissingConfigPath
	}

	// get relative file path
	_, err := util.ParseRelativePath(configPath)
	if err != nil {
		return err
	}

	// validate file path
	if err := util.ValidateFile(afs, configPath); err != nil {
		return err
	}

	return nil
}
