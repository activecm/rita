package viewer

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/activecm/rita/v5/database"

	"github.com/charmbracelet/bubbles/list"
)

// can pass in filter here so that users can pass in a search as a cmdline flag
// func GetCSVOutput(items []list.Item, relativeTimestamp time.Time) string {
func GetCSVOutput(db *database.DB, minTimestamp, relativeTimestamp time.Time, search string, limit int) (string, error) {
	// parse the search input
	filter, parseErr := ParseSearchInput(search)
	if parseErr != "" {
		return "", fmt.Errorf("error parsing search input: %s", parseErr)
	}

	// default to 100 results if no limit is specified
	pageSize := 100
	if limit > 0 {
		pageSize = limit
	}

	// get results from the database
	items, _, err := GetResults(db, filter, 0, pageSize, minTimestamp)
	if err != nil {
		return "", err
	}

	// format the results into CSV
	return FormatToCSV(items, relativeTimestamp)

}

func FormatToCSV(items []list.Item, relativeTimestamp time.Time) (string, error) {
	// if len(items) == 0 {
	// 	return "", fmt.Errorf("no items to format")
	// }

	// define the columns for the CSV output
	columns := []string{
		"Severity",
		"Source IP",
		"Destination IP",
		"FQDN",
		"Beacon Score",
		"Strobe",
		"Total Duration",
		"Long Connection Score",
		"Subdomains",
		"C2 Over DNS Score",
		"Threat Intel",
		"Prevalence",
		"First Seen",
		"Missing Host Header",
		"Connection Count",
		"Total Bytes",
		"Port:Proto:Service",
	}

	// loop over the results and format into rows and columns
	var data []string
	for _, row := range items {
		item, ok := row.(Item)
		if !ok {
			return "", fmt.Errorf("error casting item to Item")
		}
		fields := []string{
			item.GetSeverity(false), item.Src.String(), item.Dst.String(), item.FQDN,
			fmt.Sprint(item.BeaconScore), strconv.FormatBool(item.StrobeScore > 0),
			fmt.Sprint(item.TotalDuration), fmt.Sprint(item.LongConnScore),
			fmt.Sprint(item.Subdomains), fmt.Sprint(item.C2OverDNSScore), strconv.FormatBool(item.ThreatIntelScore > 0),
			fmt.Sprint(item.Prevalence), item.GetFirstSeen(relativeTimestamp), strconv.FormatBool(item.MissingHostCount > 0),
			fmt.Sprint(item.Count), fmt.Sprint(item.TotalBytes), fmt.Sprintf("\"%s\"", strings.Join(item.PortProtoService, ",")),
		}
		// create comma-delimited string from each field in this row
		formattedRow := strings.Join(fields, ",")
		data = append(data, formattedRow)
	}

	// combine the columns and data into a CSV output
	csvOutput := []string{
		strings.Join(columns, ","),
		// print comma-delimited rows, one per line
		strings.Join(data, "\n"),
	}
	// print comma-delimited columns
	return strings.Join(csvOutput, "\n"), nil
}
