package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/lab"
	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var (
	ErrLabDatabaseRequired = errors.New("database name is required")
	ErrLabTimeRange        = errors.New("--from and --to must be specified together, or both omitted")
	ErrLabMinimumScore     = errors.New("minimum score must be between 0 and 100")
)

var LabCommand = &cli.Command{
	Name:  "lab",
	Usage: "generate asset-aware laboratory reports from RITA analysis data",
	Subcommands: []*cli.Command{
		labReportCommand,
		labEvaluateCommand,
	},
}

var labReportCommand = &cli.Command{
	Name:      "report",
	Usage:     "write explainable Markdown, CSV, and HTML laboratory reports",
	UsageText: "rita lab report <database> [options]",
	Flags: append([]cli.Flag{
		&cli.StringFlag{Name: "lab-config", Usage: "load laboratory configuration from FILE", Required: true},
		&cli.StringFlag{Name: "from", Usage: "inclusive UTC RFC3339 report start"},
		&cli.StringFlag{Name: "to", Usage: "exclusive UTC RFC3339 report end"},
		&cli.StringFlag{Name: "window", Usage: "aggregation window duration", Value: ""},
		&cli.StringFlag{Name: "formats", Usage: "comma-separated: markdown,csv,html", Value: "markdown,csv,html"},
		&cli.StringFlag{Name: "output-dir", Usage: "directory for generated reports", Value: "./rita-lab-output"},
		&cli.Float64Flag{Name: "minimum-score", Usage: "minimum laboratory priority (0-100)", Value: 0},
		&cli.BoolFlag{Name: "exclude-allowlisted", Usage: "omit alerts that match the laboratory allowlist", Value: false},
		&cli.BoolFlag{Name: "overwrite", Usage: "replace an existing report file", Value: false},
	}, ConfigFlag(false)),
	Action: runLabReport,
}

var labEvaluateCommand = &cli.Command{
	Name:      "evaluate",
	Usage:     "run a controlled Zeek-log import and emit actual report measurements",
	UsageText: "rita lab evaluate <database> --logs DIRECTORY [options]",
	Flags: append([]cli.Flag{
		&cli.StringFlag{Name: "lab-config", Usage: "load laboratory configuration from FILE", Required: true},
		&cli.StringFlag{Name: "logs", Usage: "controlled Zeek log directory", Required: true},
		&cli.StringFlag{Name: "from", Usage: "inclusive UTC RFC3339 report start"},
		&cli.StringFlag{Name: "to", Usage: "exclusive UTC RFC3339 report end"},
		&cli.StringFlag{Name: "window", Usage: "aggregation window duration", Value: ""},
		&cli.StringFlag{Name: "formats", Usage: "comma-separated: markdown,csv,html", Value: "markdown,csv,html"},
		&cli.StringFlag{Name: "output-dir", Usage: "directory for generated reports", Value: "./rita-lab-output"},
		&cli.BoolFlag{Name: "exclude-allowlisted", Usage: "omit alerts that match the laboratory allowlist", Value: false},
		&cli.BoolFlag{Name: "rebuild", Usage: "destroy and rebuild the named experiment database", Value: false},
		&cli.BoolFlag{Name: "overwrite", Usage: "replace an existing report file", Value: false},
	}, ConfigFlag(false)),
	Action: runLabEvaluate,
}

func runLabReport(cCtx *cli.Context) error {
	return runLabReportWithTiming(cCtx, nil, time.Time{})
}

func runLabEvaluate(cCtx *cli.Context) error {
	if !cCtx.Args().Present() {
		return ErrLabDatabaseRequired
	}
	if err := ValidateDatabaseName(cCtx.Args().First()); err != nil {
		return err
	}
	fs := afero.NewOsFs()
	if err := ValidateLogDirectory(fs, cCtx.String("logs")); err != nil {
		return err
	}
	cfg, err := config.ReadFileConfig(fs, cCtx.String("config"))
	if err != nil {
		return err
	}
	started := time.Now()
	results, err := RunImportCmd(started, cfg, fs, cCtx.String("logs"), cCtx.Args().First(), false, cCtx.Bool("rebuild"))
	if err != nil {
		return err
	}
	return runLabReportWithTiming(cCtx, &results, started)
}

func runLabReportWithTiming(cCtx *cli.Context, importResults *ImportResults, importStartedAt time.Time) error {
	if !cCtx.Args().Present() {
		return ErrLabDatabaseRequired
	}
	databaseName := cCtx.Args().First()
	if err := ValidateDatabaseName(databaseName); err != nil {
		return err
	}
	if cCtx.Float64("minimum-score") < 0 || cCtx.Float64("minimum-score") > 100 {
		return ErrLabMinimumScore
	}

	fs := afero.NewOsFs()
	cfg, err := config.ReadFileConfig(fs, cCtx.String("config"))
	if err != nil {
		return err
	}
	labCfg, configHash, err := lab.ReadConfig(cCtx.String("lab-config"))
	if err != nil {
		return err
	}
	window, err := labWindow(cCtx.String("window"), labCfg.Reporting.DefaultWindow)
	if err != nil {
		return err
	}
	formats, err := lab.ParseFormats(cCtx.String("formats"))
	if err != nil {
		return err
	}

	db, err := database.ConnectToDB(context.Background(), databaseName, cfg, nil)
	if err != nil {
		return err
	}
	defer db.Conn.Close()
	from, to, err := labTimeRange(cCtx.String("from"), cCtx.String("to"), db)
	if err != nil {
		return err
	}

	started := time.Now()
	report, err := lab.BuildReport(db, labCfg, configHash, from, to, window)
	if err != nil {
		return err
	}
	report = lab.FilterReport(report, cCtx.Float64("minimum-score"), !cCtx.Bool("exclude-allowlisted"))
	if importResults != nil {
		report = lab.WithEvaluation(report, lab.NewEvaluationResult(importResults.ResultCounts, importStartedAt, time.Since(started), len(report.Alerts)))
	}
	paths, err := lab.WriteReportFiles(report, cCtx.String("output-dir"), formats, cCtx.Bool("overwrite"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		fmt.Fprintln(os.Stdout, path)
	}
	return nil
}

func labWindow(value, fallback string) (time.Duration, error) {
	if value == "" {
		value = fallback
	}
	window, err := time.ParseDuration(value)
	if err != nil || window <= 0 {
		return 0, fmt.Errorf("invalid --window %q", value)
	}
	return window, nil
}

func labTimeRange(fromString, toString string, db *database.DB) (time.Time, time.Time, error) {
	if (fromString == "") != (toString == "") {
		return time.Time{}, time.Time{}, ErrLabTimeRange
	}
	if fromString == "" {
		from, to, _, _, err := db.GetTrueMinMaxTimestamps()
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return from.UTC(), to.UTC().Add(time.Second), nil
	}
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(fromString))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse --from: %w", err)
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(toString))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse --to: %w", err)
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, ErrLabTimeRange
	}
	return from.UTC(), to.UTC(), nil
}
