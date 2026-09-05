package lab

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"
)

func NewReport(database string, from, to time.Time, window time.Duration, configSHA256, scoringVersion string, alerts []AggregateAlert) Report {
	SortAlerts(alerts)
	return Report{
		Database: database, GeneratedAt: time.Now().UTC(), From: from.UTC(), To: to.UTC(), Window: window,
		ConfigSHA256: configSHA256, ScoringVersion: scoringVersion, Alerts: alerts,
	}
}

func WriteMarkdown(writer io.Writer, report Report) error {
	if _, err := fmt.Fprintf(writer, "# RITA-Lab Threat Hunting Report\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "- Generated (UTC): %s\n- Database: `%s`\n- Data range: `%s` to `%s` (exclusive)\n- Aggregation window: `%s`\n- Lab configuration SHA-256: `%s`\n- Scoring version: `%s`\n", report.GeneratedAt.Format(time.RFC3339), report.Database, report.From.Format(time.RFC3339), report.To.Format(time.RFC3339), report.Window, report.ConfigSHA256, report.ScoringVersion); err != nil {
		return err
	}
	if report.Evaluation != nil {
		if _, err := fmt.Fprintf(writer, "- Evaluation: %s; imported records: %d; aggregated alerts: %d; report duration: %s\n", report.Evaluation.Status, report.Evaluation.ImportedRecords, report.Evaluation.AggregatedAlerts, report.Evaluation.ReportDuration.Round(time.Millisecond)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer, "\nThis report preserves RITA's native evidence and adds a laboratory triage priority. The laboratory priority does not replace a RITA detection conclusion."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "\n## Alert summary\n\n| Priority | Source | Destination | Type | First seen | Last seen | Allowlisted |\n|---:|---|---|---|---|---|---|"); err != nil {
		return err
	}
	for _, alert := range report.Alerts {
		if _, err := fmt.Fprintf(writer, "| %.2f | %s | %s | %s | %s | %s | %t |\n", alert.LabPriorityScore, alert.SourceIP, alert.Destination, alert.DetectionType, alert.FirstSeen.UTC().Format(time.RFC3339), alert.LastSeen.UTC().Format(time.RFC3339), alert.Allowlist.Matched); err != nil {
			return err
		}
	}
	for _, alert := range report.Alerts {
		if _, err := fmt.Fprintf(writer, "\n## %s — %s → %s\n\n", alert.AlertID, alert.SourceIP, alert.Destination); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "- Detection type: `%s`\n- Window: `%s` to `%s` (exclusive)\n- Native events: %d; connection count: %d; DNS query count: %d\n- Asset: `%s` (%s, importance %d, zone %s)\n- Lab priority: **%.2f/100** (pre-allowlist %.4f)\n", alert.DetectionType, alert.WindowStart.Format(time.RFC3339), alert.WindowEnd.Format(time.RFC3339), len(alert.NativeEvidence), alert.ConnectionCount, alert.DNSQueryCount, alert.Asset.Asset.AssetID, alert.Asset.Asset.AssetType, alert.Asset.Asset.Importance, alert.Asset.Asset.NetworkZone, alert.LabPriorityScore, alert.PreAllowlistScore); err != nil {
			return err
		}
		if alert.Allowlist.Matched {
			if _, err := fmt.Fprintf(writer, "- Allowlist: matched `%s`; reduction %.4f; reason: %s\n", alert.Allowlist.Rule.Pattern, alert.Allowlist.Rule.ScoreReduction, alert.Allowlist.Rule.Reason); err != nil {
				return err
			}
		}
		if alert.DNSFeatures.Available {
			if _, err := fmt.Fprintf(writer, "- DNS evidence: %d queries, %d unique labels, average/max label length %.2f/%d, entropy %.4f bits/byte, NXDOMAIN ratio %.4f\n", alert.DNSFeatures.QueryCount, alert.DNSFeatures.UniqueEncodedLabels, alert.DNSFeatures.AverageLabelLength, alert.DNSFeatures.MaximumLabelLength, alert.DNSFeatures.LabelEntropyBitsPerByte, alert.DNSFeatures.NXDOMAINRatio); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer, "\n### Score explanation\n\n| Component | Raw | Normalized | Weight | Contribution | Status | Reason |\n|---|---:|---:|---:|---:|---|---|"); err != nil {
			return err
		}
		for _, score := range alert.ScoreBreakdown {
			if _, err := fmt.Fprintf(writer, "| %s | %.4f | %.4f | %.4f | %.4f | %s | %s |\n", score.Name, score.RawValue, score.NormalizedValue, score.Weight, score.SignedContribution, score.Status, score.Reason); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(writer, "\n## Interpretation notes\n\nDNS entropy, label length, frequency, and NXDOMAIN ratio are investigation features. They do not independently prove DNS tunneling. Metrics are only produced by `rita lab evaluate` from actual fixture runs; absent metrics are reported as `not_measured`.")
	return err
}

func WriteCSV(writer io.Writer, report Report) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	if err := csvWriter.Write([]string{"alert_id", "window_start", "window_end", "source_ip", "destination_domain", "destination_kind", "detection_type", "first_seen", "last_seen", "connection_count", "dns_query_count", "beacon_score", "dns_score", "threat_intel_hit", "asset_id", "asset_type", "owner", "asset_importance", "network_zone", "allowlisted", "allowlist_rule", "allowlist_reason", "allowlist_reduction", "lab_priority_score", "score_breakdown_json"}); err != nil {
		return err
	}
	for _, alert := range report.Alerts {
		breakdown, err := json.Marshal(alert.ScoreBreakdown)
		if err != nil {
			return err
		}
		row := []string{
			alert.AlertID, alert.WindowStart.Format(time.RFC3339), alert.WindowEnd.Format(time.RFC3339), alert.SourceIP.String(), alert.Destination, alert.DestinationKind, alert.DetectionType,
			alert.FirstSeen.Format(time.RFC3339), alert.LastSeen.Format(time.RFC3339), strconv.FormatUint(alert.ConnectionCount, 10), strconv.FormatUint(alert.DNSQueryCount, 10),
			strconv.FormatFloat(alert.BeaconScore, 'f', -1, 64), strconv.FormatFloat(alert.DNSScore, 'f', -1, 64), strconv.FormatBool(alert.ThreatIntelHit),
			alert.Asset.Asset.AssetID, alert.Asset.Asset.AssetType, alert.Asset.Asset.Owner, strconv.Itoa(alert.Asset.Asset.Importance), alert.Asset.Asset.NetworkZone,
			strconv.FormatBool(alert.Allowlist.Matched), alert.Allowlist.Rule.Pattern, alert.Allowlist.Rule.Reason, strconv.FormatFloat(alert.Allowlist.Rule.ScoreReduction, 'f', -1, 64), strconv.FormatFloat(alert.LabPriorityScore, 'f', -1, 64), string(breakdown),
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	return csvWriter.Error()
}

var htmlReportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RITA-Lab Threat Hunting Report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccd1d1;padding:.4rem;text-align:left}th{background:#ecf0f1}section{margin:2rem 0}.score{font-weight:700}code{white-space:pre-wrap}</style></head>
<body><h1>RITA-Lab Threat Hunting Report</h1><p><strong>Laboratory priority is triage context, not a replacement for RITA native detection conclusions.</strong></p>
<ul><li>Database: <code>{{.Database}}</code></li><li>Generated (UTC): {{.GeneratedAt}}</li><li>Data range: {{.From}} to {{.To}} (exclusive)</li><li>Window: {{.Window}}</li><li>Configuration SHA-256: <code>{{.ConfigSHA256}}</code></li><li>Scoring version: {{.ScoringVersion}}</li>{{if .Evaluation}}<li>Evaluation: {{.Evaluation.Status}}; imported records: {{.Evaluation.ImportedRecords}}; aggregated alerts: {{.Evaluation.AggregatedAlerts}}; report duration: {{.Evaluation.ReportDuration}}</li>{{end}}</ul>
<h2>Alerts</h2><table><thead><tr><th>Priority</th><th>Source</th><th>Destination</th><th>Type</th><th>Asset</th><th>Allowlist</th></tr></thead><tbody>{{range .Alerts}}<tr><td class="score">{{printf "%.2f" .LabPriorityScore}}</td><td>{{.SourceIP}}</td><td>{{.Destination}}</td><td>{{.DetectionType}}</td><td>{{.Asset.Asset.AssetID}}</td><td>{{if .Allowlist.Matched}}{{.Allowlist.Rule.Pattern}}{{end}}</td></tr>{{end}}</tbody></table>
{{range .Alerts}}<section><h2>{{.AlertID}}</h2><p><b>{{.DetectionType}}</b>: {{.SourceIP}} → {{.Destination}}; {{.FirstSeen}}–{{.LastSeen}}; native events {{len .NativeEvidence}}.</p>
<p>Asset: {{.Asset.Asset.AssetID}} (importance {{.Asset.Asset.Importance}}). {{if .Allowlist.Matched}}Allowlist: {{.Allowlist.Rule.Pattern}}; reduction {{printf "%.4f" .Allowlist.Rule.ScoreReduction}}; reason: {{.Allowlist.Rule.Reason}}.{{end}}</p>
{{if .DNSFeatures.Available}}<p>DNS: {{.DNSFeatures.QueryCount}} queries; {{.DNSFeatures.UniqueEncodedLabels}} unique labels; entropy {{printf "%.4f" .DNSFeatures.LabelEntropyBitsPerByte}} bits/byte; NXDOMAIN ratio {{printf "%.4f" .DNSFeatures.NXDOMAINRatio}}.</p>{{end}}
<table><thead><tr><th>Component</th><th>Raw</th><th>Normalized</th><th>Weight</th><th>Contribution</th><th>Status</th><th>Reason</th></tr></thead><tbody>{{range .ScoreBreakdown}}<tr><td>{{.Name}}</td><td>{{printf "%.4f" .RawValue}}</td><td>{{printf "%.4f" .NormalizedValue}}</td><td>{{printf "%.4f" .Weight}}</td><td>{{printf "%.4f" .SignedContribution}}</td><td>{{.Status}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody></table></section>{{end}}
</body></html>`))

func WriteHTML(writer io.Writer, report Report) error {
	return htmlReportTemplate.Execute(writer, report)
}

func RenderMarkdown(report Report) (string, error) {
	var output bytes.Buffer
	if err := WriteMarkdown(&output, report); err != nil {
		return "", err
	}
	return output.String(), nil
}

func ReportFileExtension(format string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "markdown", "md":
		return "md", true
	case "csv":
		return "csv", true
	case "html":
		return "html", true
	default:
		return "", false
	}
}
