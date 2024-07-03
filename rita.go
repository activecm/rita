package main

import (
	"fmt"
	"log"
	"os"

	"github.com/activecm/ritav2/cmd"
	"github.com/activecm/ritav2/config"
	"github.com/activecm/ritav2/logger"
	"github.com/activecm/ritav2/viewer"

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
	fmt.Fprintf(c.App.ErrWriter, "\n\n\t[!] %+v\n\n", err.Error())
	cli.OsExiter(1)

}
