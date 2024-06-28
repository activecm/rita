package cmd

import (
	"activecm/rita/config"
	"activecm/rita/database"
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var ListCommand = &cli.Command{
	Name:        "list",
	Usage:       "list available datasets",
	UsageText:   "list",
	Description: "lists available datasets",
	Args:        false,
	Flags: []cli.Flag{
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {

		// check if too many arguments were provided
		if cCtx.NArg() > 0 {
			return ErrTooManyArguments
		}

		// set up file system interface
		afs := afero.NewOsFs()

		// run the delete command
		if err := runListCmd(afs, cCtx.String("config")); err != nil {
			return err
		}

		return nil
	},
}

func runListCmd(afs afero.Fs, configPath string) error {

	cfg, err := config.LoadConfig(afs, configPath)
	if err != nil {
		return err
	}

	// connect to server
	server, err := database.ConnectToServer(context.Background(), cfg)
	if err != nil {
		return err
	}

	dbs, err := server.ListImportDatabases()
	if err != nil {
		return err
	}

	if len(dbs) == 0 {
		fmt.Println("No available datasets.")
	}

	t := FormatListTable(dbs)
	fmt.Println(t)
	return nil
}

func FormatListTable(dbs []database.ImportDatabase) *table.Table {
	var data [][]string

	for _, d := range dbs {
		data = append(data, []string{d.Name, strconv.FormatBool(d.Rolling), fmt.Sprintf("%s - %s", d.MinTS.Format("2006-01-02 15:04"), d.MaxTS.Format("2006-01-02 15:04"))})
	}

	re := lipgloss.NewRenderer(os.Stdout)
	baseStyle := re.NewStyle().Padding(0, 1)
	headerStyle := baseStyle.Foreground(lipgloss.Color("252")).Bold(true)

	headers := []string{"Name", "Rolling", "Time Range (UTC)"}
	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(re.NewStyle().Foreground(lipgloss.Color("238"))).
		Headers(headers...).
		Rows(data...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == 0 {
				return headerStyle
			}

			even := row%2 == 0

			if even {
				return baseStyle.Foreground(lipgloss.Color("245"))
			}
			return baseStyle.Foreground(lipgloss.Color("252"))
		})
	return t
}
