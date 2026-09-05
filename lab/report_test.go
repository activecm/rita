package lab

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReportFormatsEscapeStructuredContent(t *testing.T) {
	cfg := testConfig(t)
	when := time.Date(2026, 1, 1, 0, 15, 0, 0, time.UTC)
	alerts, err := AggregateEvidence([]NativeEvidence{{
		SourceIP: net.ParseIP("10.1.2.3"), FQDN: "host.updates.example.test", Count: 3,
		FirstSeen: when.Add(-time.Minute), LastSeen: when, BeaconScore: .8, BeaconThreatScore: .8, NetworkSize: 1,
	}}, nil, cfg, 30*time.Minute)
	require.NoError(t, err)
	alerts[0].Allowlist.Rule.Reason = "owner, \"quoted\"\nnew line <script>alert(1)</script>"
	report := NewReport("lab_traffic", when.Add(-time.Hour), when.Add(time.Hour), 30*time.Minute, "abc", "v1", alerts)

	var csvOutput bytes.Buffer
	require.NoError(t, WriteCSV(&csvOutput, report))
	require.Contains(t, csvOutput.String(), "\"owner, \"\"quoted\"\"\nnew line <script>alert(1)</script>\"")

	var htmlOutput bytes.Buffer
	require.NoError(t, WriteHTML(&htmlOutput, report))
	require.NotContains(t, htmlOutput.String(), "<script>alert(1)</script>")
	require.Contains(t, htmlOutput.String(), "&lt;script&gt;")

	markdown, err := RenderMarkdown(report)
	require.NoError(t, err)
	require.True(t, strings.Contains(markdown, "RITA-Lab Threat Hunting Report"))
}

func TestParseFormats(t *testing.T) {
	formats, err := ParseFormats(" markdown,CSV,html ")
	require.NoError(t, err)
	require.Equal(t, []string{"markdown", "csv", "html"}, formats)
	_, err = ParseFormats("pdf")
	require.Error(t, err)
}
