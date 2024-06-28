package main

import (
	"activecm/rita/cmd"
	"activecm/rita/config"
	"activecm/rita/logger"
	"activecm/rita/util"
	"activecm/rita/viewer"
	"fmt"
	"log"
	"os"

	"github.com/google/go-github/github"
	"github.com/joho/godotenv"
	"github.com/urfave/cli/v2"
)

// Version is populated by build flags with the current Git tag
var Version string

func main() {
	// set the version in config to make it more importable by other packages
	config.Version = Version

	// UNIX Time is faster and smaller than most timestamps
	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	app := &cli.App{
		EnableBashCompletion: true,
		Commands:             cmd.Commands(),
		Name:                 "RITA",
		Usage:                "Look for evil needles in big haystacks",
		UsageText:            "rita [-d] command [command options]",
		Version:              Version,
		Args:                 true,
		ExitErrHandler:       exitErrHandler,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "debug",
				Aliases:  []string{"d"},
				Usage:    "Run in debug mode",
				Value:    false, // default config file path
				Required: false,
			},
		},
		Before: func(cCtx *cli.Context) error {
			// set logger mode based on APP_ENV
			logger.DebugMode = os.Getenv("APP_ENV") == "dev"

			// override APP_ENV if the --debug flag is set
			// *note that global flags must be placed before the subcommand when running in the CLI
			if cCtx.Bool("debug") {
				logger.DebugMode = true
				viewer.DebugMode = true
			}

			// load environment variables from .env files
			// base .env file is required
			err := godotenv.Load("./.env")
			if err != nil {
				log.Fatal("Error loading .env file", err)
			}

			// check for update if version is set
			if Version != "" {
				newer, latestVersion, err := util.CheckForNewerVersion(github.NewClient(nil), "v0.0.0")
				if err != nil {
					log.Fatalf("Error checking for newer version: %v", err)
				}
				if newer {
					fmt.Printf("\n\t✨ A newer version (%s) of RITA is available! https://github.com/activecm/rita/releases ✨\n", latestVersion)
				}
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger := logger.GetLogger()
		logger.Fatal().Err(err).Send()
	}

}

// exitErrHandler implements cli.ExitErrHandlerFunc
func exitErrHandler(c *cli.Context, err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(c.App.ErrWriter, "\n[!] %+v\n", err.Error())
	cli.OsExiter(1)

}
