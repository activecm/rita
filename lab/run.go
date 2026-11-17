package lab

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/activecm/rita/v5/database"
)

func BuildReport(db *database.DB, cfg *LabConfig, configSHA256 string, from, to time.Time, window time.Duration) (Report, error) {
	evidence, err := QueryNativeEvidence(db, from, to)
	if err != nil {
		return Report{}, err
	}
	var dnsEvents []DNSEvent
	if cfg.DNSFeatures.Enabled {
		dnsEvents, err = QueryDNSEvents(db, from, to, DNSEvidenceDomains(evidence))
		if err != nil {
			return Report{}, err
		}
	}
	alerts, err := AggregateEvidence(evidence, dnsEvents, cfg, window)
	if err != nil {
		return Report{}, err
	}
	return NewReport(db.GetSelectedDB(), from, to, window, configSHA256, cfg.Scoring.Version, alerts), nil
}

func FilterReport(report Report, minimumScore float64, includeAllowlisted bool) Report {
	alerts := make([]AggregateAlert, 0, len(report.Alerts))
	for _, alert := range report.Alerts {
		if alert.LabPriorityScore < minimumScore || (!includeAllowlisted && alert.Allowlist.Matched) {
			continue
		}
		alerts = append(alerts, alert)
	}
	report.Alerts = alerts
	return report
}

func WriteReportFiles(report Report, outputDir string, formats []string, overwrite bool) ([]string, error) {
	if len(formats) == 0 {
		return nil, fmt.Errorf("at least one report format is required")
	}

	paths := make([]string, 0, len(formats))
	seen := make(map[string]struct{})
	for _, format := range formats {
		extension, ok := ReportFileExtension(format)
		if !ok {
			return nil, fmt.Errorf("unsupported report format %q", format)
		}
		if _, duplicate := seen[extension]; duplicate {
			continue
		}
		seen[extension] = struct{}{}
		paths = append(paths, filepath.Join(outputDir, "rita-lab-report."+extension))
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one report format is required")
	}
	for _, path := range paths {
		if overwrite {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("refusing to overwrite %s; pass --overwrite to replace it", path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	type renderFunc func(io.Writer) error
	renders := make([]renderFunc, len(paths))
	for i, path := range paths {
		switch filepath.Ext(path) {
		case ".md":
			renders[i] = func(writer io.Writer) error { return WriteMarkdown(writer, report) }
		case ".csv":
			renders[i] = func(writer io.Writer) error { return WriteCSV(writer, report) }
		case ".html":
			renders[i] = func(writer io.Writer) error { return WriteHTML(writer, report) }
		}
	}
	for i, path := range paths {
		tmp, err := os.CreateTemp(outputDir, ".rita-lab-report-*")
		if err != nil {
			return nil, err
		}
		tmpName := tmp.Name()
		if err := renders[i](tmp); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpName)
			return nil, err
		}
		if err := os.Rename(tmpName, path); err != nil {
			_ = os.Remove(tmpName)
			return nil, err
		}
	}
	return paths, nil
}

func ParseFormats(value string) ([]string, error) {
	formats := strings.Split(value, ",")
	result := make([]string, 0, len(formats))
	for _, format := range formats {
		format = strings.TrimSpace(strings.ToLower(format))
		if _, ok := ReportFileExtension(format); !ok {
			return nil, fmt.Errorf("unsupported report format %q", format)
		}
		result = append(result, format)
	}
	if len(result) == 0 || (len(result) == 1 && result[0] == "") {
		return nil, fmt.Errorf("at least one report format is required")
	}
	return result, nil
}
