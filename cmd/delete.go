package cmd

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"

	"github.com/manifoldco/promptui"
	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ErrTrimmedNameEmpty = errors.New("trimmed name cannot contain wildcards or be empty")

var DeleteCommand = &cli.Command{
	Name:        "delete",
	Usage:       "delete a dataset",
	UsageText:   "delete [NAME]",
	Description: "if <dataset name> ends in a wildcard, all datasets with that prefix will be deleted",
	Args:        false,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:     "non-interactive",
			Aliases:  []string{"ni"},
			Usage:    "does not prompt for confirmation of deletion",
			Value:    false,
			Required: false,
		},
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {
		// check if too many arguments were provided
		if cCtx.NArg() > 1 {
			return ErrTooManyArguments
		}

		// check if a database name was provided
		if !cCtx.Args().Present() {
			return ErrMissingDatabaseName
		}

		input := cCtx.Args().First()

		// trim leading and trailing wildcards
		trimmedName, err := TrimWildcards(input)
		if err != nil {
			return err
		}

		// set up file system interface
		afs := afero.NewOsFs()

		// validate the trimmed name
		if err := ValidateDatabaseName(trimmedName); err != nil {
			return err
		}

		prompt := true
		if cCtx.Bool("non-interactive") {
			prompt = false
		}

		// load config file
		cfg, err := config.ReadFileConfig(afs, cCtx.String("config"))
		if err != nil {
			return err
		}

		// run the delete command
		if err := RunDeleteCmd(cfg, input, trimmedName, prompt); err != nil {
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cfg); err != nil {
			return err
		}

		return nil
	},
}

func RunDeleteCmd(cfg *config.Config, entry string, trimmedName string, ask bool) error {

	// validate the trimmed name
	if len(trimmedName) == 0 {
		return ErrTrimmedNameEmpty
	}

	// connect to server
	server, err := database.ConnectToServer(context.Background(), cfg)
	if err != nil {
		return err
	}

	// set uo prompt for confirmation
	prompt := promptui.Prompt{
		Label:     "Delete Dataset",
		IsConfirm: true,
	}

	wildcardStart := strings.HasPrefix(entry, "*")
	wildcardEnd := strings.HasSuffix(entry, "*")
	if wildcardStart || wildcardEnd {
		fmt.Printf("Deleting databases matching: %s\n", entry)
		switch {
		case wildcardStart && !wildcardEnd:
			fmt.Printf("Deleting databases ending with: %s\n", trimmedName)
		case !wildcardStart && wildcardEnd:
			fmt.Printf("Deleting databases beginning with: %s\n", trimmedName)
		case wildcardStart && wildcardEnd:
			fmt.Printf("Deleting databases containing: %s\n", trimmedName)
		default:
			return errors.New("unable to determine wildcard status for dataset deletion")
		}

		if ask {
			if _, err := prompt.Run(); err != nil {
				fmt.Println("Cancelling deletion...")
				return err
			}
		}

		numDeleted, err := server.DropMultipleSensorDatabases(trimmedName, wildcardStart, wildcardEnd)
		if err != nil {
			return err
		}
		if numDeleted == 0 {
			fmt.Println("Found no matching datasets to delete.")
		} else {
			fmt.Println("Successfully deleted", numDeleted, "datasets")
		}
	} else {
		fmt.Printf("Deleting database: %s\n", entry)

		if ask {
			if _, err := prompt.Run(); err != nil {
				fmt.Println("Cancelling deletion...")
				return err
			}
		}

		if err := server.DeleteSensorDB(entry); err != nil {
			return err
		}

		fmt.Println("Successfully deleted dataset if it existed.")
	}

	return nil
}

// TrimWildcards removes leading and trailing wildcards from a database name
func TrimWildcards(dbName string) (string, error) {
	// regex to remove leading and trailing wildcards
	re := regexp.MustCompile(`^\*+|\*+$`)
	trimmedName := re.ReplaceAllString(dbName, "")

	// check if the trimmed name contains any wildcards or is empty
	if strings.Contains(trimmedName, "*") || len(trimmedName) == 0 {
		return "", ErrTrimmedNameEmpty
	}

	return trimmedName, nil
}
