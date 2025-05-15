package cmd

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/activecm/rita/v5/amalgamation"
	"github.com/activecm/rita/v5/analysis"
	"github.com/activecm/rita/v5/config"
	c "github.com/activecm/rita/v5/constants"
	"github.com/activecm/rita/v5/database"
	i "github.com/activecm/rita/v5/importer"
	zlog "github.com/activecm/rita/v5/logger"
	m "github.com/activecm/rita/v5/modifier"
	"github.com/activecm/rita/v5/util"

	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"
)

var (
	numParsers   = 8 // largest impact
	numDigesters = 8
	numWriters   = 12 // 2nd largest impact
)

// for rolling datasets, limit the logs that are imported to the past 14 (to match the snapshot tables) + 1 (for good luck) days
const RollingLogDaysToKeep = 15

// util.Max(1, runtime.NumCPU()/2)
var ErrInsufficientReadPermissions = errors.New("file does not have readable permission or does not exist")
var ErrNoValidFilesFound = errors.New("no valid log files found")
var ErrInvalidLogHourFormat = errors.New("could not parse hour from log file name - invalid format")
var ErrInvalidLogHourRange = errors.New("could not parse hour from log file name - hour out of range")
var ErrInvalidLogType = errors.New("incompatible log type")
var ErrIncompatibleFileExtension = errors.New("incompatible file extension")
var ErrSkippedDuplicateLog = errors.New("encountered file with same name but different extension, skipping file due to older last modified time")
var ErrMissingLogDirectory = errors.New("log directory flag is required")

type WalkError struct {
	Path  string
	Error error
}
type HourlyZeekLogs []map[string][]string

var ImportCommand = &cli.Command{
	Name:      "import",
	Usage:     "import zeek logs into a target database",
	UsageText: "rita import [--database NAME] [-logs DIRECTORY] [--rolling] [--rebuild]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "database",
			Aliases:  []string{"d"},
			Usage:    "target database; database name should start with a lowercase letter, should contain only alphanumeric and underscores, and not end with an underscore",
			Required: true,
			Action: func(_ *cli.Context, name string) error {
				return ValidateDatabaseName(name)
			},
		},
		&cli.StringFlag{
			Name:     "logs",
			Aliases:  []string{"l"},
			Usage:    "path to log directory",
			Required: false,
			Action: func(_ *cli.Context, path string) error {
				return ValidateLogDirectory(afero.NewOsFs(), path)
			},
		},
		&cli.BoolFlag{
			Name:     "rolling",
			Aliases:  []string{"r"},
			Usage:    "indicates rolling import, which builds on and removes data to maintain a fixed length of time",
			Value:    false,
			Required: false,
		},
		&cli.BoolFlag{
			Name:     "rebuild",
			Aliases:  []string{"x"},
			Usage:    "destroys existing database and imports given files",
			Value:    false,
			Required: false,
		},
		ConfigFlag(false),
	},
	Action: func(cCtx *cli.Context) error {
		afs := afero.NewOsFs()

		// load config file
		cfg, err := config.ReadFileConfig(afs, cCtx.String("config"))
		if err != nil {
			return err
		}

		// TODO: do we need to move this into RunImportCmd?

		// set the import start time in microseconds
		startTime := time.Now()

		// run import command
		_, err = RunImportCmd(startTime, cfg, afs, cCtx.String("logs"), cCtx.String("database"), cCtx.Bool("rolling"), cCtx.Bool("rebuild"))
		if err != nil {
			return err
		}

		// check for updates after running the command
		if err := CheckForUpdate(cfg); err != nil {
			return err
		}

		return nil
	},
}

type ImportTimestamps struct {
	MinTS       time.Time
	MaxTS       time.Time
	MinTSBeacon time.Time
	maxTSBeacon time.Time
}
type ImportResults struct {
	i.ResultCounts
	ImportID         []util.FixedString
	ImportTimestamps []ImportTimestamps
}

func RunImportCmd(startTime time.Time, cfg *config.Config, afs afero.Fs, logDir string, dbName string, rolling bool, rebuild bool) (ImportResults, error) {
	// set the number of workers based on the number of CPUs
	numParsers = int(math.Floor(math.Max(4, float64(runtime.NumCPU())/2)))
	numDigesters = int(math.Floor(math.Max(4, float64(runtime.NumCPU())/2)))
	numWriters = int(math.Floor(math.Max(4, float64(runtime.NumCPU())/2)))

	var importResults ImportResults
	logger := zlog.GetLogger()

	// keep track of the cumulative elapsed time
	importStartedAt := startTime

	logger.Info().Str("directory", logDir).Bool("rolling", rolling).Bool("rebuild", rebuild).Str("dataset", dbName).Str("started_at", importStartedAt.String()).Msg("Initiating new import...")

	// load dataset relative to the current working directory
	// this is done here instead of in the flag parsing so that anyone calling RunImportCmd will have the relative path
	logDir, err := util.ParseRelativePath(logDir)
	if err != nil {
		return importResults, err
	}

	// create import database if it doesn't already exist and connect to it
	db, err := database.SetUpNewImport(afs, cfg, dbName, rolling, rebuild)
	if err != nil {
		return importResults, err
	}

	// get list of hourly log maps of all days of log files in directory
	logMap, walkErrors, err := WalkFiles(afs, logDir, db.Rolling)
	if err != nil {
		return importResults, err
	}

	// log any errors that occurred during the walk
	for _, walkErr := range walkErrors {
		logger.Debug().Str("path", walkErr.Path).Err(walkErr.Error).Msg("file was left out of import due to error or incompatibility")
	}

	var elapsedTime int64

	// loop through each day
	for day, hourlyLogs := range logMap {
		if len(logMap) > 1 {
			logger.Info().Str("started_at", importStartedAt.String()).Msg(fmt.Sprintf("Importing day %d/%d", day+1, len(logMap)))
		}

		dayStart := time.Now()

		// loop through each hour's log files
		for hour, files := range hourlyLogs {

			logger.Debug().Msg(fmt.Sprintf("------------- STARTING HOUR %v!! -------------", hour))
			hourStart := time.Now()
			// count the number of files in this hour
			totalFileCount := 0
			for zeekType := range files {
				totalFileCount += len(files[zeekType])
			}

			// check that this hour contains files
			// walkFiles errors if it found no files
			// GetHourlyLogMap errors if it has no files left in any hour after filtering out invalid combinations of files
			// We still need to skip importing if there are no files for this hour
			if totalFileCount < 1 {
				logger.Debug().Str("hour", fmt.Sprint(hour)).Msg("no valid files were selected for this hour's import")
				// don't exit the rest of the import just because this hour doesn't contain any logs
				continue
			}

			// log the start of the import
			logger.Debug().Str("started_at", importStartedAt.String()).Msg(fmt.Sprintf("Importing hour %d/%d", hour+1, len(hourlyLogs)))

			// reset temporary tables
			err = db.ResetTemporaryTables()
			if err != nil {
				return importResults, err
			}

			// set up new importer
			importer, err := i.NewImporter(db, cfg, importStartedAt, numDigesters, numParsers, numWriters)
			if err != nil {
				return importResults, err
			}

			// import the data
			err = importer.Import(afs, files)
			if err != nil && !errors.Is(err, i.ErrAllFilesPreviouslyImported) {
				return importResults, err
			}

			// skip the rest of this hour's import if all files have been previously imported
			if errors.Is(err, i.ErrAllFilesPreviouslyImported) {
				continue
			}

			// update result counts (used for testing)
			importResults.Conn += importer.ResultCounts.Conn
			importResults.OpenConn += importer.ResultCounts.OpenConn
			importResults.HTTP += importer.ResultCounts.HTTP
			importResults.OpenHTTP += importer.ResultCounts.OpenHTTP
			importResults.DNS += importer.ResultCounts.DNS
			importResults.UDNS += importer.ResultCounts.UDNS
			importResults.PDNSRaw += importer.ResultCounts.PDNSRaw
			importResults.SSL += importer.ResultCounts.SSL
			importResults.OpenSSL += importer.ResultCounts.OpenSSL
			importResults.ImportID = append(importResults.ImportID, importer.ImportID)
			logger.Debug().Msg("------------- RUNNING ANALYSIS!! -------------")

			// TODO pull useCurrentTime out of beacon?
			minTSBeacon, maxTSBeacon, _, err := db.GetBeaconMinMaxTimestamps()
			missingBeaconTS := errors.Is(err, database.ErrInvalidMinMaxTimestamp)
			if err != nil && !missingBeaconTS {
				return importResults, fmt.Errorf("could not find min/max timestamps for beaconing analysis: %w", err)
			}

			minTS, maxTS, _, useCurrentTime, err := db.GetTrueMinMaxTimestamps()
			if err != nil {
				logger.Error().Err(err).Int("day", day).Int("hour", hour).Msg("could not find imported data. Be sure to include your internal subnets in 'filter.internal_subnets' in config.hjson.")
				continue
				// return importResults, fmt.Errorf("could not find imported data. Be sure to include your internal subnets in 'filter.internal_subnets' in config.hjson.\n(err: %w)", err)
			}

			importResults.ImportTimestamps = append(importResults.ImportTimestamps, ImportTimestamps{
				MinTS:       minTS,
				MaxTS:       maxTS,
				MinTSBeacon: minTSBeacon,
				maxTSBeacon: maxTSBeacon,
			})

			logger.Debug().Time("min_ts", minTS).Time("max_ts", maxTS).Time("min_beacon_ts", minTSBeacon).Time("max_beacon_ts", maxTSBeacon).Bool("skip_beaconing", missingBeaconTS).Msg("timestamps used in analysis")

			// set up new analyzer
			analyzer, err := analysis.NewAnalyzer(db, cfg, importer.ImportID, minTS, maxTS, minTSBeacon, maxTSBeacon, useCurrentTime, missingBeaconTS)
			if err != nil {
				return importResults, err
			}

			// analyze the data
			err = analyzer.Analyze()
			if err != nil {
				return importResults, err
			}

			// set up new modifier
			modifier, err := m.NewModifier(db, cfg, importer.ImportID, minTS)
			if err != nil {
				return importResults, err
			}

			// modify the data
			err = modifier.Modify()
			if err != nil {
				return importResults, err
			}

			// set up new amalgamation
			amalgamation := amalgamation.NewAmalgamator(db, &importer.ImportID, cfg)
			if err := amalgamation.Amalgamate(); err != nil {
				return importResults, err
			}

			// add import finished record to metadatabase
			err = db.AddImportFinishedRecordToMetaDB(importer.ImportID, minTS, maxTS)
			if err != nil {
				return importResults, err
			}

			// get the elapsed time for this hour
			elapsedTime += time.Since(hourStart).Nanoseconds()

			// add the duration of this hour's import to the importStartedAt time for the next import
			importStartedAt = importStartedAt.Add(time.Duration(elapsedTime) * time.Nanosecond)

			logger.Info().Str("elapsed_time", time.Since(hourStart).String()).Int("day", day).Int("hour", hour).Msg("Finished Importing Hour Chunk")

		}

		// only print finish message per day if there were multiple days
		if len(logMap) > 1 {
			logger.Info().Str("elapsed_time", time.Since(dayStart).String()).Int("day", day).Msg("Finished Importing Day")
		}
	}

	// if after going through every day/hour and there are no import IDs, return error stating all files were previously imported
	if len(importResults.ImportID) == 0 {
		return importResults, i.ErrAllFilesPreviouslyImported
	}
	logger.Info().Str("elapsed_time", fmt.Sprintf("%1.1fs", time.Since(startTime).Seconds())).Msg("🎊✨ Finished Import! ✨🎊")

	return importResults, nil
}

func ValidateLogDirectory(afs afero.Fs, logDir string) error {
	if logDir == "" {
		return ErrMissingLogDirectory
	}

	dir, err := util.ParseRelativePath(logDir)
	if err != nil {
		return err
	}

	// check if directory exists
	if err := util.ValidateDirectory(afs, dir); err != nil {
		return err
	}

	return nil
}

func ValidateDatabaseName(name string) error {
	if name == "" {
		return ErrMissingDatabaseName
	}

	// regex to validate dataset name
	re := regexp.MustCompile("^[a-z]{1}([A-Za-z_0-9])+[A-Za-z0-9]$")

	switch {
	case len(name) > 63:
		return fmt.Errorf("\n\t[!] database name cannot exceed 63 characters: %v", name)
	case name == "default" || name == "system" || name == "information_schema" || name == "metadatabase":
		return fmt.Errorf("\n\t[!] database name cannot be reserved word %v", name)
	case unicode.IsUpper(rune(name[0])):
		return fmt.Errorf("\n\t[!] database name must start with a lowercase letter %v", name)
	case strings.Contains(name, "-"):
		return fmt.Errorf("\n\t[!] database name cannot contain hyphens %v", name)
	case !re.MatchString(name):
		return fmt.Errorf("\n\t[!] database name is invalid. %v", name)

	}
	return nil
}

// ParseFolderDate extracts the date from a given folder name
func ParseFolderDate(folder string) (time.Time, error) {
	if folder == "" {
		return time.Unix(0, 0), errors.New("folder name cannot be empty")
	}

	// check if the path is a directory
	folderDate, err := time.Parse(time.DateOnly, folder)
	if err != nil {
		// put non-date folders into some generic folder like 2006-01-02
		folderDate, err = time.Parse(time.DateOnly, "2006-01-02")
		if err != nil {
			return time.Unix(0, 0), err
		}
	}
	return folderDate, nil
}

// WalkFiles starts a goroutine to walk the directory tree at root and send the
// path of each regular file on the string channel.  It sends the result of the
// walk on the error channel.  If done is closed, WalkFiles abandons its work.
func WalkFiles(afs afero.Fs, root string, rolling bool) ([]HourlyZeekLogs, []WalkError, error) {
	// check if root is a valid directory or file
	err := util.ValidateDirectory(afs, root)
	if err != nil && !errors.Is(err, util.ErrPathIsNotDir) {
		return nil, nil, err
	}
	if err != nil && errors.Is(err, util.ErrPathIsNotDir) {
		if err := util.ValidateFile(afs, root); err != nil {
			return nil, nil, err
		}
	}

	logMap := make(map[time.Time]HourlyZeekLogs)

	totalFilesFound, hour0FilesFound := 0, 0

	type fileTrack struct {
		lastModified time.Time
		path         string
	}
	fTracker := make(map[string]fileTrack)

	var walkErrors []WalkError

	err = afero.Walk(afs, root, func(path string, info os.FileInfo, afErr error) error {

		// check if afero failed to access or find a file or directory
		if afErr != nil {
			walkErrors = append(walkErrors, WalkError{Path: path, Error: afErr})
			return nil //nolint:nilerr // log the issue and continue walking
		}

		// skip if path is a directory
		if info.IsDir() {
			return nil
		}

		// skip if file is not a compatible log file
		if !(strings.HasSuffix(path, ".log") || strings.HasSuffix(path, ".gz")) {
			walkErrors = append(walkErrors, WalkError{Path: path, Error: ErrIncompatibleFileExtension})
			return nil // log the issue and continue walking
		}

		// check if the file is readable
		_, err := afs.Open(path)
		if err != nil || !(info.Mode().Perm()&0444 == 0444) {
			walkErrors = append(walkErrors, WalkError{Path: path, Error: ErrInsufficientReadPermissions})
			return nil //nolint:nilerr // log the issue and continue walking
		}

		// trim the path name to remove the file extensions, only to leave .log
		trimmedFileName := strings.TrimSuffix(path, ".gz")

		// check if path doesn't have .log suffix anymore and add it if not
		if !strings.HasSuffix(trimmedFileName, ".log") {
			trimmedFileName += ".log"
		}

		// check if the file entry exists and get the existing entry if it does
		fileData, exists := fTracker[trimmedFileName]

		switch {
		// add file if it hasn't been seen before
		case !exists:
			fTracker[trimmedFileName] = fileTrack{
				lastModified: info.ModTime(),
				path:         path,
			}
		// if trimmed version of the file exists in the map and the currently marked file for import
		// was last modified more recently than this current file, replace it with this file
		case exists && fileData.lastModified.Before(info.ModTime()):

			// warn the user so that this isn't a silent operation
			walkErrors = append(walkErrors, WalkError{Path: fTracker[trimmedFileName].path, Error: ErrSkippedDuplicateLog})
			// logger.Warn().Str("original_path", fTracker[trimmedFileName].path).Str("replacement_path", path).Msg("encountered file with same name but different extension, potential duplicate log, skipping")

			fTracker[trimmedFileName] = fileTrack{
				lastModified: info.ModTime(),
				path:         path,
			}
		// if the current file is older than the one we have already seen or no other conditions are met, skip it
		default:
			walkErrors = append(walkErrors, WalkError{Path: path, Error: ErrSkippedDuplicateLog})

		}

		return nil
	})

	// return an error if the file walk failed completely
	if err != nil {
		return nil, nil, fmt.Errorf("file walk failed: %w", err)
	}

	// group files into arrays by their log type
	for _, file := range fTracker {
		path := file.path

		// check if the file is one of the accepted log types
		var prefix string
		switch {
		case strings.HasPrefix(filepath.Base(path), c.ConnPrefix) && !strings.HasPrefix(filepath.Base(path), c.ConnSummaryPrefixUnderscore) && !strings.HasPrefix(filepath.Base(path), c.ConnSummaryPrefixHyphen):
			prefix = c.ConnPrefix
		case strings.HasPrefix(filepath.Base(path), c.OpenConnPrefix):
			prefix = c.OpenConnPrefix
		case strings.HasPrefix(filepath.Base(path), c.DNSPrefix):
			prefix = c.DNSPrefix
		case strings.HasPrefix(filepath.Base(path), c.HTTPPrefix):
			prefix = c.HTTPPrefix
		case strings.HasPrefix(filepath.Base(path), c.OpenHTTPPrefix):
			prefix = c.OpenHTTPPrefix
		case strings.HasPrefix(filepath.Base(path), c.SSLPrefix):
			prefix = c.SSLPrefix
		case strings.HasPrefix(filepath.Base(path), c.OpenSSLPrefix):
			prefix = c.OpenSSLPrefix
		default: // skip file if it doesn't match any of the accepted prefixes
			walkErrors = append(walkErrors, WalkError{Path: path, Error: ErrInvalidLogType})
			continue
		}

		// parse the hour from the filename
		hour, err := ParseHourFromFilename(file.path)
		if err != nil {
			walkErrors = append(walkErrors, WalkError{Path: path, Error: err})
			continue
		}

		parentDir := filepath.Base(filepath.Dir(file.path))
		folderDate, err := ParseFolderDate(parentDir)
		if err != nil {
			walkErrors = append(walkErrors, WalkError{Path: path, Error: err})
		}

		// Check if the entry for the day exists, if not, initialize it
		if _, ok := logMap[folderDate]; !ok {
			logMap[folderDate] = make(HourlyZeekLogs, 24)
		}

		// Check if the entry for the hour exists, if not, initialize it
		if logMap[folderDate][hour] == nil {
			logMap[folderDate][hour] = make(map[string][]string)
		}

		// add the file to the hour map
		logMap[folderDate][hour][prefix] = append(logMap[folderDate][hour][prefix], path)

	}

	// filter out invalid file combinations

	// loop over each day in the log map
	for day := range logMap {

		// loop over each hour in the day
		for hour := range logMap[day] {

			// // if there are no conn logs in the hour, we have to skip any SSL and HTTP logs for that hour
			// if len(logMap[day][hour][i.ConnPrefix]) == 0 && (len(logMap[day][hour][i.SSLPrefix]) > 0 || len(logMap[day][hour][i.HTTPPrefix]) > 0) {
			// 	logger.Warn().Msg("SSL / HTTP logs are present, but no conn logs exist, skipping SSL / HTTP logs...")
			// 	delete(logMap[day][hour], i.SSLPrefix)
			// 	delete(logMap[day][hour], i.HTTPPrefix)
			// }

			// // 	// if there are no open conn logs in the hour, we have to skip any open SSL and open HTTP logs for that hour
			// if len(logMap[day][hour][i.OpenConnPrefix]) == 0 && (len(logMap[day][hour][i.OpenSSLPrefix]) > 0 || len(logMap[day][hour][i.OpenHTTPPrefix]) > 0) {
			// 	logger.Warn().Msg("Open SSL / open HTTP logs are present, but no conn logs exist, skipping open SSL / open HTTP logs...")
			// 	delete(logMap[day][hour], i.OpenSSLPrefix)
			// 	delete(logMap[day][hour], i.OpenHTTPPrefix)
			// }

			// // track the total number of files after filtering out invalid file combinations
			// for zeekType := range logMap[day][hour] {
			// 	// sort the files for each log type, necessary for tests
			// 	slices.Sort(logMap[day][hour][zeekType])
			// 	totalFilesFound += len(logMap[day][hour][zeekType])
			// 	if hour == 0 {
			// 		hour0FilesFound += len(logMap[day][hour][zeekType])
			// 	}
			// }

			totalHourFilesFound := database.ValidateLogCombinations(logMap[day][hour])
			totalFilesFound += totalHourFilesFound
			if hour == 0 {
				hour0FilesFound += totalHourFilesFound
			}
		}
	}

	// return an error if no files were found
	if totalFilesFound == 0 {
		return nil, walkErrors, ErrNoValidFilesFound
	}

	var days []time.Time
	for day := range logMap {
		days = append(days, day)
	}

	// for rolling logs, limit the logs that are included to RollingLogDaysToKeep as long as there was at least one log folder in the past N days
	importLogs := GatherDailyLogs(logMap, days, rolling)

	return importLogs, walkErrors, err
}

func GatherDailyLogs(logMap map[time.Time]HourlyZeekLogs, days []time.Time, rolling bool) []HourlyZeekLogs {
	shouldFilter := false

	// sort days by oldest to newest
	slices.SortFunc(days, func(a, b time.Time) int { return a.Compare(b) })

	// determine if there are any logs that are in the range to keep
	today := time.Now().Truncate(24 * time.Hour)
	nDaysAgo := today.Add(time.Duration(-RollingLogDaysToKeep) * 24 * time.Hour)

	// only filter rolling!
	if rolling {
		//  determine if there are any logs that are in the range to keep by checking the newest day (last in the array)
		if days[len(days)-1].Compare(nDaysAgo) > -1 {
			shouldFilter = true
		}
	}

	var importLogs []HourlyZeekLogs

	// build hourly zeek logs (for both rolling and non-rolling)
	for _, day := range days {
		if shouldFilter {
			// if day is too old, skip adding it to the import logs array
			if day.Compare(nDaysAgo) == -1 {
				continue
			}
		}
		importLogs = append(importLogs, logMap[day])
	}
	return importLogs
}

// ParseHourFromFilename extracts the hour from a given filename
func ParseHourFromFilename(filename string) (int, error) {
	// define regex patterns to extract the hour from the filename
	timePattern := `[A-Za-z]+\.(\d{2})[:/_]\d{2}`

	// compile the timeRegex
	timeRegex := regexp.MustCompile(timePattern)

	// attempt to find a match in the filename
	matches := timeRegex.FindStringSubmatch(filename)

	// if hour pattern didn't match, check if filename is a security onion log or simple log file
	if matches == nil {
		timePatternSecOnion := `[A-Za-z]+[:/_]\d{8}[:/_](\d{2})[:/_]\d{2}`

		// attempt to match the second onion pattern
		// compile the timeRegex
		timeRegex := regexp.MustCompile(timePatternSecOnion)

		// attempt to find a match in the filename
		matches = timeRegex.FindStringSubmatch(filename)

		if matches == nil {
			// regex to identify simple log files (ie, conn.log, open_conn.log, /logs/conn.log.gz, etc) without hour
			simpleLogPattern := `^\w+\.log(\.gz)?$`
			simpleLogRegex := regexp.MustCompile(simpleLogPattern)

			// if the filename matches the simple log pattern, consider file as 0 hour and return
			if simpleLogRegex.MatchString(filepath.Base(filename)) {
				return 0, nil
			}

			// if format doesn't match the hourly pattern or the simple log pattern, return an error
			// to catch malformed hour formats
			return 0, ErrInvalidLogHourFormat
		}
	}

	// convert the extracted hour string to an integer
	hour, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, ErrInvalidLogHourFormat
	}

	// ensure the hour is in the 0-23 range
	if hour < 0 || hour > 23 {
		return 0, ErrInvalidLogHourRange
	}

	return hour, nil
}
