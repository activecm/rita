package viewer_test

import (
	"net"
	"testing"
	"time"

	"github.com/activecm/rita/v5/viewer"

	"github.com/charmbracelet/bubbles/list"
	"github.com/stretchr/testify/require"
)

const expectedCSVHeader = "Severity,Source IP,Destination IP,FQDN,Beacon Score,Strobe,Total Duration,Long Connection Score,Subdomains,C2 Over DNS Score,Threat Intel,Prevalence,First Seen,Missing Host Header,Connection Count,Total Bytes,Port:Proto:Service,Modifiers\n"

// func (s *ViewerTestSuite) TestGetCSVOutput() {
// 	// minTimestamp, maxTimestamp, _, useCurrentTime, err := s.db.GetBeaconMinMaxTimestamps()
// 	minTimestamp, maxTimestamp, _, useCurrentTime, err := s.db.GetTrueMinMaxTimestamps()
// 	s.Require().NoError(err)
// 	s.Require().False(useCurrentTime, "CSV output test dataset shouldn't use the current time for first seen")

// 	tests := []struct {
// 		name              string
// 		minTimestamp      time.Time
// 		relativeTimestamp time.Time
// 		search            string
// 		limit             int
// 		expectedCSV       string
// 		expectedError     bool
// 	}{
// 		{
// 			name:              "unfiltered result",
// 			relativeTimestamp: maxTimestamp,
// 			minTimestamp:      minTimestamp,
// 			search:            "",
// 			limit:             1,
// 			expectedCSV: expectedCSVHeader +
// 				`Critical,10.55.100.103,::,www.alexa.com,0.899,false,119027.91,0.8,0,0,false,0.8666667,23 hours ago,false,602,47747442,"443:tcp:ssl,80:tcp:http","mime_type_mismatch:288,rare_signature:Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.16299.98"`,
// 			expectedError: false,
// 		},
// 	}

// 	for _, test := range tests {
// 		s.T().Run(test.name, func(t *testing.T) {
// 			require := require.New(t)

// 			// run the function
// 			csv, err := viewer.GetCSVOutput(s.db, test.minTimestamp, test.relativeTimestamp, test.search, test.limit)

// 			// check if error was expected
// 			require.Equal(test.expectedError, err != nil, "expected error to be %v, but got %v", test.expectedError, err)

// 			// check if the output is as expected
// 			require.Equal(test.expectedCSV, csv, "expected csv to be %v, but got %v", test.expectedCSV, csv)
// 		})
// 	}
// }

func (s *ViewerTestSuite) TestFormatToCSV() {

	tests := []struct {
		name              string
		data              []list.Item
		relativeTimestamp time.Time
		expectedCSV       string
		expectedError     bool
	}{
		{
			name: "simple result",
			data: []list.Item{
				list.Item(&viewer.Item{
					Src:                      net.ParseIP("10.55.100.111"),
					Dst:                      net.ParseIP("88.221.81.192"),
					FQDN:                     "example.com",
					FinalScore:               0.8,
					Count:                    2574,
					BeaconScore:              0.75,
					StrobeScore:              0,
					BeaconThreatScore:        0,
					TotalDuration:            10800,
					LongConnScore:            0.8,
					FirstSeen:                time.Now().Add(-3 * 24 * time.Hour),
					FirstSeenScore:           -0.15,
					Prevalence:               0.35,
					PrevalenceScore:          0,
					Subdomains:               3,
					PortProtoService:         []string{"80:tcp:http", "443:tcp:https"},
					C2OverDNSScore:           0.45,
					ThreatIntelScore:         0.1,
					ThreatIntelDataSizeScore: 0.1,
					TotalBytes:               24335500,
					TotalBytesFormatted:      "23.21 MiB",
					MissingHostHeaderScore:   0.1,
					MissingHostCount:         0,
				}),
			},
			relativeTimestamp: time.Now(),
			expectedCSV: expectedCSVHeader +
				"High,10.55.100.111,88.221.81.192,example.com,0.75,false,10800,0.8,3,0.45,true,0.35,3 days ago,false,2574,24335500,\"80:tcp:http,443:tcp:https\",\"\"",
			expectedError: false,
		},
		{
			name:              "empty result",
			data:              []list.Item{},
			relativeTimestamp: time.Now(),
			expectedCSV:       expectedCSVHeader,
			expectedError:     false,
		},
	}

	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			csv, err := viewer.FormatToCSV(test.data, test.relativeTimestamp)

			// check if error was expected
			require.Equal(test.expectedError, err != nil, "expected error to be %v, but got %v", test.expectedError, err)

			// check if the output is as expected
			require.Equal(test.expectedCSV, csv, "expected csv to be %v, but got %v", test.expectedCSV, csv)
		})
	}

}
