package cmd

import (
	"errors"
	"fmt"

	"github.com/activecm/ritav2/config"
	"github.com/activecm/ritav2/util"

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
		if err := RunValidateConfigCommand(afs, cCtx.String("config")); err != nil {
			fmt.Printf("\n\t[!] Configuration file is not valid...")
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cCtx, afero.NewOsFs()); err != nil {
			return err
		}

		return nil
	},
}

func RunValidateConfigCommand(afs afero.Fs, configPath string) error {
	// validate config file path
	if err := ValidateConfigPath(afs, configPath); err != nil {
		return err
	}

	// load config path
	_, err := config.LoadConfig(afs, configPath)
	if err != nil {
		return err
	}

	fmt.Printf("\n\t[✨] Configuration file is valid \n\n")

	return nil
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
