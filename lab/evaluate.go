package lab

import (
	"time"

	"github.com/activecm/rita/v5/importer"
)

func NewEvaluationResult(importResults importer.ResultCounts, started time.Time, reportDuration time.Duration, aggregatedAlerts int) EvaluationResult {
	return EvaluationResult{
		ImportStartedAt:  started,
		ReportDuration:   reportDuration,
		ImportedRecords:  importResults.Conn + importResults.OpenConn + importResults.HTTP + importResults.OpenHTTP + importResults.DNS + importResults.PDNSRaw + importResults.SSL + importResults.OpenSSL,
		AggregatedAlerts: aggregatedAlerts,
		Status:           "measured",
	}
}

func WithEvaluation(report Report, result EvaluationResult) Report {
	report.Evaluation = &result
	return report
}
