package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/activecm/rita/v5/util"
	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// defaultConfigPath specifies the path of RITA's static config file
const defaultConfigPath = "../config.hjson"

func TestMain(m *testing.M) {
	// load environment variables with panic prevention
	if err := godotenv.Overload("../.env", "../integration/test.env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	os.Exit(m.Run())
}

func TestReadFileConfig(t *testing.T) {
	dfCfg := defaultConfig()
	require.NoError(t, dfCfg.setEnv())

	tests := []struct {
		name           string
		configJSON     string
		expectedConfig *Config
		expectedErrs   []string
	}{
		{
			name: "Valid Config",
			// create a JSON string to write to the temporary file
			configJSON: `{	
					update_check_enabled: false,
					http_extensions_file_path: "/path/to/http/extensions",
					batch_size: 75000,
					max_query_execution_time: 120000,
					months_to_keep_historical_first_seen: 6,
					filtering: {
						internal_subnets: ["11.0.0.0/8", "120.130.140.150/8"],
						always_included_subnets: ["13.0.0.0/8", "160.140.150.160/8"],
						always_included_domains: ["abc.com", "def.com"],
						never_included_subnets: ["12.0.0.0/8", "150.140.150.160/8"],
						never_included_domains: ["ghi.com", "jkl.com"],
						filter_external_to_internal: false,
					},
					threat_intel: {
						online_feeds: ["https://example.com/feed1", "https://example.com/feed2"]
					},
					scoring: {
						beacon: {
							unique_connection_threshold: 10,
							timestamp_score_weight: 0.35,
							datasize_score_weight: 0.20,
							duration_score_weight: 0.35,
							histogram_score_weight: 0.10,
							duration_min_hours_seen: 10,
							duration_consistency_ideal_hours_seen: 15,
							histogram_mode_sensitivity: 0.08,
							histogram_bimodal_outlier_removal: 2,
							histogram_bimodal_min_hours_seen: 15,
							score_thresholds: {
								base: 0,
								low: 1,
								medium: 2,
								high: 3
							},
						},
						long_connection_score_thresholds: {
							base: 1,
							low: 2,
							medium: 3,
							high: 4
						},
						c2_score_thresholds: {
							base: 1,
							low: 2,
							medium: 3,
							high: 4
						},
						strobe_impact: {
							category: "low",
						},
						threat_intel_impact: {
							category: "low",
						},
					},
					modifiers: {
						threat_intel_score_increase: 0.1,
						threat_intel_datasize_threshold: 100,
						prevalence_score_increase: 0.6,
						prevalence_increase_threshold: 0.1,
						prevalence_score_decrease: 0.1,
						prevalence_decrease_threshold: 0.2,
						first_seen_score_increase: 0.8,
						first_seen_increase_threshold: 10,
						first_seen_score_decrease: 0.2,
						first_seen_decrease_threshold: 50,
						missing_host_count_score_increase: 0.4,
						rare_signature_score_increase: 0.4,
						c2_over_dns_direct_conn_score_increase: 0.9,
						mime_type_mismatch_score_increase: 0.6
					},
			}`,
			expectedConfig: func() *Config {
				cfg := &Config{
					RITA: RITA{
						UpdateCheckEnabled:              false,
						BatchSize:                       75000,
						MaxQueryExecutionTime:           120000,
						MonthsToKeepHistoricalFirstSeen: 6,
						ThreatIntel: ThreatIntel{
							OnlineFeeds: []string{"https://example.com/feed1", "https://example.com/feed2"},
						},
					},

					Filtering: Filtering{
						InternalSubnets: []util.Subnet{
							{IPNet: &net.IPNet{IP: net.IP{11, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{120, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
						},
						AlwaysIncludedSubnets: []util.Subnet{
							{IPNet: &net.IPNet{IP: net.IP{13, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{160, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
						},
						// mandatoryNeverIncludeSubnets are always apended to any neverIncludedSubnet entries
						NeverIncludedSubnets: []util.Subnet{
							{IPNet: &net.IPNet{IP: net.IP{12, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{150, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{0, 0, 0, 0}.To16(), Mask: net.CIDRMask(128, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{127, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{169, 254, 0, 0}.To16(), Mask: net.CIDRMask(112, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{224, 0, 0, 0}.To16(), Mask: net.CIDRMask(100, 128)}},
							{IPNet: &net.IPNet{IP: net.IP{255, 255, 255, 255}.To16(), Mask: net.CIDRMask(128, 128)}},
							{IPNet: &net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}},
							{IPNet: &net.IPNet{IP: net.IPv6unspecified, Mask: net.CIDRMask(128, 128)}},
							{IPNet: &net.IPNet{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)}},
							{IPNet: &net.IPNet{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)}},
							{IPNet: &net.IPNet{IP: net.ParseIP("ff02::2"), Mask: net.CIDRMask(128, 128)}},
						},

						AlwaysIncludedDomains:    []string{"abc.com", "def.com"},
						NeverIncludedDomains:     []string{"ghi.com", "jkl.com"},
						FilterExternalToInternal: false,
					},

					Scoring: Scoring{
						Beacon: BeaconScoring{
							UniqueConnectionThreshold:         10,
							TimestampScoreWeight:              0.35,
							DatasizeScoreWeight:               0.20,
							DurationScoreWeight:               0.35,
							HistogramScoreWeight:              0.10,
							DurationMinHoursSeen:              10,
							DurationConsistencyIdealHoursSeen: 15,
							HistogramModeSensitivity:          0.08,
							HistogramBimodalOutlierRemoval:    2,
							HistogramBimodalMinHoursSeen:      15,
							ScoreThresholds:                   ScoreThresholds{Base: 0, Low: 1, Med: 2, High: 3},
						},
						ThreatScoring: ThreatScoring{
							LongConnectionScoreThresholds: ScoreThresholds{Base: 1, Low: 2, Med: 3, High: 4},
							C2ScoreThresholds:             ScoreThresholds{Base: 1, Low: 2, Med: 3, High: 4},
							StrobeImpact:                  ScoreImpact{Category: LowThreat, Score: LOW_CATEGORY_SCORE},
							ThreatIntelImpact:             ScoreImpact{Category: LowThreat, Score: LOW_CATEGORY_SCORE},
						},
					},
					Modifiers: Modifiers{
						ThreatIntelScoreIncrease:         0.1,
						ThreatIntelDataSizeThreshold:     100,
						PrevalenceScoreIncrease:          0.6,
						PrevalenceIncreaseThreshold:      0.1,
						PrevalenceScoreDecrease:          0.1,
						PrevalenceDecreaseThreshold:      0.2,
						FirstSeenScoreIncrease:           0.8,
						FirstSeenIncreaseThreshold:       10,
						FirstSeenScoreDecrease:           0.2,
						FirstSeenDecreaseThreshold:       50,
						MissingHostCountScoreIncrease:    0.4,
						RareSignatureScoreIncrease:       0.4,
						C2OverDNSDirectConnScoreIncrease: 0.9,
						MIMETypeMismatchScoreIncrease:    0.6,
					},
				}
				require.NoError(t, cfg.setEnv())
				return cfg
			}(),
		},
		{
			name:         "Invalid JSON",
			configJSON:   `{filtering: { internal_subnets: }}`,
			expectedErrs: []string{errReadingConfigFile.Error(), "check your syntax"},
		},
		{
			name:           "Empty Categories",
			configJSON:     `{Env: {}, RITA: {}, Filtering: {}, Scoring: {}, Modifiers: {}}`,
			expectedConfig: &dfCfg,
		},
		{
			name:           "Empty Config Object",
			configJSON:     `{}`,
			expectedConfig: &dfCfg,
		},
		{
			name:         "Empty File",
			configJSON:   ``,
			expectedErrs: []string{util.ErrFileIsEmtpy.Error()},
		},
		{
			name:         "File Not Found",
			expectedErrs: []string{util.ErrFileDoesNotExist.Error()},
		},
		// the following tests ensure validation for subnets, since those checks are done outside of the validator package and cannot
		// be vetted with the other validation tests
		{
			name:         "Internal Subnets - Invalid IPv4",
			configJSON:   `{filtering: { internal_subnets: ["bingbong", "chickenstrip"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), util.ErrParseCIDRInvalidIP.Error()},
		},
		{
			name:         "Internal Subnets - Invalid IPv6",
			configJSON:   `{filtering: { internal_subnets: [ "2001:db8::chickenstrip"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), util.ErrParseCIDRInvalidIP.Error()},
		},
		{
			name:         "Internal Subnets - Invalid IPv4-Mapped IPv6",
			configJSON:   `{filtering: { internal_subnets: ["::ffff:beepboop"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), util.ErrParseCIDRInvalidIP.Error()},
		},
		{
			name:         "Internal Subnets - Invalid IPv4 Mask",
			configJSON:   `{filtering: { internal_subnets: ["bingbong.com/33"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), (&net.ParseError{Type: "CIDR address", Text: ""}).Error()},
		},
		{
			name:         "Internal Subnets - Invalid IPv4-Mapped IPv6 Mask",
			configJSON:   `{filtering: { internal_subnets: ["::ffff:192.168.1.0/b"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), util.ErrParseCIDRInvalidMask.Error()},
		},
		{
			name:         "Internal Subnets - Invalid IPv6 Mask",
			configJSON:   `{filtering: { internal_subnets: ["2001:db8::1/a"]}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), (&net.ParseError{Type: "CIDR address", Text: ""}).Error()},
		},
		{
			name:         "Internal Subnets Empty",
			configJSON:   `{filtering: { internal_subnets: []}}`,
			expectedErrs: []string{errReadingConfigFile.Error(), "'InternalSubnets' failed on the 'gt' tag"},
		},
		{
			name:           "Never Included Subnets Empty",
			configJSON:     `{filtering: { never_included_subnets: []}}`,
			expectedConfig: &dfCfg, // mandatory never include will ensure they are never empty
		},
		{
			name:           "Always Included Subnets Empty",
			configJSON:     `{filtering: { always_included_subnets: []}}`,
			expectedConfig: &dfCfg, // always included subnets are optional
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// create mock file system in memory
			afs := afero.NewMemMapFs()

			// get config file path
			configPath := fmt.Sprintf("test-config-%d.hjson", i)

			// create file
			if tc.name != "File Not Found" {
				require.NoError(t, afero.WriteFile(afs, configPath, []byte(tc.configJSON), 0o775))
				defer func() { require.NoError(t, afs.Remove(configPath)) }()
			}

			// call function
			cfg, err := ReadFileConfig(afs, configPath)

			if len(tc.expectedErrs) == 0 {
				require.NoError(t, err)

				// need this so the test doesn't just crash on the next lines if something isn't working as expected
				require.NotNil(t, cfg, "Config should not be nil")
				require.NotNil(t, tc.expectedConfig, "Expected config should not be nil")

				// verify version got set
				require.Equal(t, "dev", Version, "version should be 'dev'")

				// verify that env variables are not overwritten by JSON
				require.Equal(t, tc.expectedConfig.Env, cfg.Env, "Env should match expected value")

				// verify that the retrived config matches the expected config (split up for easier debugging)
				require.Equal(t, tc.expectedConfig.RITA, cfg.RITA, "RITA should match expected value")
				require.Equal(t, tc.expectedConfig.Filtering, cfg.Filtering, "Filtering should match expected value")
				require.Equal(t, tc.expectedConfig.Scoring, cfg.Scoring, "Scoring should match expected value")
				require.Equal(t, tc.expectedConfig.Modifiers, cfg.Modifiers, "Modifiers should match expected value")

				// all together
				require.Equal(t, tc.expectedConfig, cfg, "config should match expected value")

			} else {
				// verify that error was received
				require.Error(t, err)

				// check validation errors
				checkValidationErrs(t, tc.expectedErrs, err.Error())

				// check that the config is nil
				require.Nil(t, cfg, "Config should be nil")
			}

		})
	}

}

func TestConfig_Validate(t *testing.T) {
	type testCase struct {
		name         string
		config       func(*Config)
		expectedErrs []string
	}

	tests := []struct {
		group string
		cases []testCase
	}{
		{"Valid", []testCase{
			{name: "Default", config: func(cfg *Config) {}},
		}},
		{"Env", []testCase{
			{name: "DBConnection Not Host:Port", config: func(cfg *Config) { cfg.Env.DBConnection = "invalid" }, expectedErrs: []string{"'DBConnection' failed on the 'hostname_port' tag"}},
			{name: "HTTPExtensionsFilePath Not Valid File", config: func(cfg *Config) { cfg.Env.HTTPExtensionsFilePath = "--" }, expectedErrs: []string{"'HTTPExtensionsFilePath' failed on the 'file' tag"}},
			{name: "LogLevel < Min", config: func(cfg *Config) { cfg.Env.LogLevel = -1 }, expectedErrs: []string{"'LogLevel' failed on the 'min' tag"}},
			{name: "LogLevel > Max", config: func(cfg *Config) { cfg.Env.LogLevel = 7 }, expectedErrs: []string{"'LogLevel' failed on the 'max' tag"}},
			{name: "ThreatIntelCustomFeedsDirectory Not Valid Dir", config: func(cfg *Config) { cfg.Env.ThreatIntelCustomFeedsDirectory = "--" }, expectedErrs: []string{"'ThreatIntelCustomFeedsDirectory' failed on the 'dir' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Env = Env{} }, expectedErrs: []string{"'Env' failed on the 'required' tag"}},
		}},
		{"RITA", []testCase{
			{name: "BatchSize < Range", config: func(cfg *Config) { cfg.RITA.BatchSize = 24999 }, expectedErrs: []string{"'BatchSize' failed on the 'gte' tag"}},
			{name: "BatchSize > Range", config: func(cfg *Config) { cfg.RITA.BatchSize = 2000001 }, expectedErrs: []string{"'BatchSize' failed on the 'lte' tag"}},
			{name: "MaxQueryExecutionTime < Range", config: func(cfg *Config) { cfg.RITA.MaxQueryExecutionTime = 0 }, expectedErrs: []string{"'MaxQueryExecutionTime' failed on the 'gte' tag"}},
			{name: "MaxQueryExecutionTime > Range", config: func(cfg *Config) { cfg.RITA.MaxQueryExecutionTime = 2000001 }, expectedErrs: []string{"'MaxQueryExecutionTime' failed on the 'lte' tag"}},
			{name: "MonthsToKeepHistoricalFirstSeen < Range", config: func(cfg *Config) { cfg.RITA.MonthsToKeepHistoricalFirstSeen = 0 }, expectedErrs: []string{"'MonthsToKeepHistoricalFirstSeen' failed on the 'gte' tag"}},
			{name: "MonthsToKeepHistoricalFirstSeen > Range", config: func(cfg *Config) { cfg.RITA.MonthsToKeepHistoricalFirstSeen = 61 }, expectedErrs: []string{"'MonthsToKeepHistoricalFirstSeen' failed on the 'lte' tag"}},
			{name: "ThreatIntel.OnlineFeeds Not URLs", config: func(cfg *Config) { cfg.RITA.ThreatIntel.OnlineFeeds = []string{"invalid"} }, expectedErrs: []string{"'OnlineFeeds[0]' failed on the 'url' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.RITA = RITA{} }, expectedErrs: []string{"'RITA' failed on the 'required' tag"}},
		}},
		{"Filtering", []testCase{
			// should never be set to empty
			{name: "InternalSubnets Nil", config: func(cfg *Config) { cfg.Filtering.InternalSubnets = nil }, expectedErrs: []string{"'InternalSubnets' failed on the 'required' tag"}},
			{name: "InternalSubnets Empty", config: func(cfg *Config) { cfg.Filtering.InternalSubnets = []util.Subnet{} }, expectedErrs: []string{"'InternalSubnets' failed on the 'gt' tag"}},
			// should never be empty after mandatory subnets are added
			{name: "NeverIncludedSubnets Nil", config: func(cfg *Config) { cfg.Filtering.NeverIncludedSubnets = nil }, expectedErrs: []string{"'NeverIncludedSubnets' failed on the 'required' tag"}},
			{name: "NeverIncludedSubnets Empty", config: func(cfg *Config) { cfg.Filtering.NeverIncludedSubnets = []util.Subnet{} }, expectedErrs: []string{"'NeverIncludedSubnets' failed on the 'gt' tag"}},
			{name: "AlwaysIncludedDomains Not Domains", config: func(cfg *Config) { cfg.Filtering.AlwaysIncludedDomains = []string{"notadomain"} }, expectedErrs: []string{"'AlwaysIncludedDomains[0]' failed on the 'fqdn' tag"}},
			{name: "AlwaysIncludedDomains Mixed Validity", config: func(cfg *Config) { cfg.Filtering.AlwaysIncludedDomains = []string{"valid.com", "notadomain"} }, expectedErrs: []string{"'AlwaysIncludedDomains[1]' failed on the 'fqdn' tag"}},
			{name: "NeverIncludedDomains Not Domains", config: func(cfg *Config) { cfg.Filtering.NeverIncludedDomains = []string{"notadomain"} }, expectedErrs: []string{"'NeverIncludedDomains[0]' failed on the 'fqdn' tag"}},
			{name: "NeverIncludedDomains Mixed Validity", config: func(cfg *Config) { cfg.Filtering.NeverIncludedDomains = []string{"valid.com", "notadomain"} }, expectedErrs: []string{"'NeverIncludedDomains[1]' failed on the 'fqdn' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Filtering = Filtering{} }, expectedErrs: []string{"'Filtering' failed on the 'required' tag"}},
		}},
		{"Scoring", []testCase{
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Scoring = Scoring{} }, expectedErrs: []string{"'Scoring' failed on the 'required' tag"}},
		}},
		{"Beacon Scoring", []testCase{
			{name: "UniqueConnectionThreshold < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.UniqueConnectionThreshold = 3 }, expectedErrs: []string{"'UniqueConnectionThreshold' failed on the 'gte' tag"}},
			{name: "TimestampScoreWeight < Range", config: func(cfg *Config) {
				cfg.Scoring.Beacon = BeaconScoring{4, -0.25, 0.75, 0.25, 0.25, 10, 15, 0.08, 2, 15, ScoreThresholds{50, 75, 90, 100}}
			}, expectedErrs: []string{"'TimestampScoreWeight' failed on the 'gte' tag"}},
			{name: "DatasizeScoreWeight < Range", config: func(cfg *Config) {
				cfg.Scoring.Beacon = BeaconScoring{4, 0.75, -0.25, 0.25, 0.25, 10, 15, 0.08, 2, 15, ScoreThresholds{50, 75, 90, 100}}
			}, expectedErrs: []string{"'DatasizeScoreWeight' failed on the 'gte' tag"}},
			{name: "DurationScoreWeight < Range", config: func(cfg *Config) {
				cfg.Scoring.Beacon = BeaconScoring{4, 0.25, 0.75, -0.25, 0.25, 10, 15, 0.08, 2, 15, ScoreThresholds{50, 75, 90, 100}}
			}, expectedErrs: []string{"'DurationScoreWeight' failed on the 'gte' tag"}},
			{name: "HistogramScoreWeight < Range", config: func(cfg *Config) {
				cfg.Scoring.Beacon = BeaconScoring{4, 0.25, 0.25, 0.75, -0.25, 10, 15, 0.08, 2, 15, ScoreThresholds{50, 75, 90, 100}}
			}, expectedErrs: []string{"'HistogramScoreWeight' failed on the 'gte' tag"}},
			{name: "Score Weight Sum != 1", config: func(cfg *Config) {
				cfg.Scoring.Beacon.TimestampScoreWeight = 0.1
				cfg.Scoring.Beacon.DatasizeScoreWeight = 0.1
				cfg.Scoring.Beacon.DurationScoreWeight = 0.1
				cfg.Scoring.Beacon.HistogramScoreWeight = 0.1
			}, expectedErrs: []string{"'TimestampScoreWeight' failed on the 'beacon_weights' tag", "'DatasizeScoreWeight' failed on the 'beacon_weights' tag", "'DurationScoreWeight' failed on the 'beacon_weights' tag", "'HistogramScoreWeight' failed on the 'beacon_weights' tag"}},
			{name: "DurationMinHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationMinHoursSeen = 0 }, expectedErrs: []string{"'DurationMinHoursSeen' failed on the 'gte' tag"}},
			{name: "DurationMinHoursSeen > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationMinHoursSeen = 25 }, expectedErrs: []string{"'DurationMinHoursSeen' failed on the 'lte' tag"}},
			{name: "DurationConsistencyIdealHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationConsistencyIdealHoursSeen = 0 }, expectedErrs: []string{"'DurationConsistencyIdealHoursSeen' failed on the 'gte' tag"}},
			{name: "DurationConsistencyIdealHoursSeen > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationConsistencyIdealHoursSeen = 25 }, expectedErrs: []string{"'DurationConsistencyIdealHoursSeen' failed on the 'lte' tag"}},
			{name: "HistogramModeSensitivity < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramModeSensitivity = -1 }, expectedErrs: []string{"'HistogramModeSensitivity' failed on the 'gte' tag"}},
			{name: "HistogramModeSensitivity > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramModeSensitivity = 25 }, expectedErrs: []string{"'HistogramModeSensitivity' failed on the 'lte' tag"}},
			{name: "HistogramBimodalOutlierRemoval < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalOutlierRemoval = -1 }, expectedErrs: []string{"'HistogramBimodalOutlierRemoval' failed on the 'gte' tag"}},
			{name: "HistogramBimodalOutlierRemoval > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalOutlierRemoval = 25 }, expectedErrs: []string{"'HistogramBimodalOutlierRemoval' failed on the 'lte' tag"}},
			{name: "HistogramBimodalMinHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalMinHoursSeen = 2 }, expectedErrs: []string{"'HistogramBimodalMinHoursSeen' failed on the 'gte' tag"}},
			{name: "HistogramBimodalMinHoursSeen > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalMinHoursSeen = 25 }, expectedErrs: []string{"'HistogramBimodalMinHoursSeen' failed on the 'lte' tag"}},
			{name: "ScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds.Base = -1 }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "ScoreThresholds High > Max", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds.High = 101 }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "ScoreThresholds Base == Low", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{75, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "ScoreThresholds Base > Low", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{76, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "ScoreThresholds Low > Med", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 91, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "ScoreThresholds Low == Med", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 90, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "ScoreThresholds Med > High", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 75, 91, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "ScoreThresholds Med == High", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 75, 90, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "Empty ScoreThresholds", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag", "'Low' failed on the 'ltfield' tag", "'Med' failed on the 'ltfield' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Scoring.Beacon = BeaconScoring{} }, expectedErrs: []string{"'Beacon' failed on the 'required' tag"}},
		}},
		{"Threat Scoring", []testCase{
			{name: "LongConnectionScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds.Base = 0 }, expectedErrs: []string{"'LongConnectionScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "LongConnectionScoreThresholds High > Max", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds.High = (24 * 3600) + 1 }, expectedErrs: []string{"'LongConnectionScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "LongConnectionScoreThresholds Base == Low", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{75, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "LongConnectionScoreThresholds Base > Low", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{76, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "LongConnectionScoreThresholds Low > Med", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{50, 91, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "LongConnectionScoreThresholds Low == Med", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{50, 90, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "LongConnectionScoreThresholds Med > High", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{50, 75, 91, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "LongConnectionScoreThresholds Med == High", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{50, 75, 90, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "Empty LongConnectionScoreThresholds", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{} }, expectedErrs: []string{"'LongConnectionScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "C2ScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds.Base = 0 }, expectedErrs: []string{"'C2ScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "C2ScoreThresholds High Should Be Unlimited", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds.High = 2147483647 }}, // max int32
			{name: "C2ScoreThresholds Base == Low", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{75, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "C2ScoreThresholds Base > Low", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{76, 75, 90, 100} }, expectedErrs: []string{"'Base' failed on the 'ltfield' tag"}},
			{name: "C2ScoreThresholds Low > Med", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{50, 91, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "C2ScoreThresholds Low == Med", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{50, 90, 90, 100} }, expectedErrs: []string{"'Low' failed on the 'ltfield' tag"}},
			{name: "C2ScoreThresholds Med > High", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{50, 75, 91, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "C2ScoreThresholds Med == High", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{50, 75, 90, 90} }, expectedErrs: []string{"'Med' failed on the 'ltfield' tag"}},
			{name: "Empty C2ScoreThresholds", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds = ScoreThresholds{} }, expectedErrs: []string{"'C2ScoreThresholds' failed on the 'score_thresholds_range' tag"}},
			{name: "StrobeImpact Category Invalid", config: func(cfg *Config) { cfg.Scoring.StrobeImpact.Category = "invalid" }, expectedErrs: []string{"'StrobeImpact' failed on the 'impact_category' tag"}},
			{name: "StrobeImpact Category Empty", config: func(cfg *Config) { cfg.Scoring.StrobeImpact.Category = "" }, expectedErrs: []string{"'StrobeImpact' failed on the 'impact_category' tag"}},
			{name: "ThreatIntelImpact Category Invalid", config: func(cfg *Config) { cfg.Scoring.ThreatIntelImpact.Category = "invalid" }, expectedErrs: []string{"'ThreatIntelImpact' failed on the 'impact_category' tag"}},
			{name: "ThreatIntelImpact Category Empty", config: func(cfg *Config) { cfg.Scoring.ThreatIntelImpact.Category = "" }, expectedErrs: []string{"'ThreatIntelImpact' failed on the 'impact_category' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Scoring.ThreatScoring = ThreatScoring{} }, expectedErrs: []string{"'ThreatScoring' failed on the 'required' tag"}},
		}},
		{"Modifiers", []testCase{
			{name: "ThreatIntelScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.ThreatIntelScoreIncrease = -0.1 }, expectedErrs: []string{"'ThreatIntelScoreIncrease' failed on the 'gte' tag"}},
			{name: "ThreatIntelScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.ThreatIntelScoreIncrease = 1.1 }, expectedErrs: []string{"'ThreatIntelScoreIncrease' failed on the 'lte' tag"}},
			{name: "ThreatIntelDataSizeThreshold < Range", config: func(cfg *Config) { cfg.Modifiers.ThreatIntelDataSizeThreshold = 0 }, expectedErrs: []string{"'ThreatIntelDataSizeThreshold' failed on the 'gte' tag"}},
			{name: "PrevalenceScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceScoreIncrease = -0.1 }, expectedErrs: []string{"'PrevalenceScoreIncrease' failed on the 'gte' tag"}},
			{name: "PrevalenceScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceScoreIncrease = 1.1 }, expectedErrs: []string{"'PrevalenceScoreIncrease' failed on the 'lte' tag"}},
			{name: "PrevalenceIncreaseThreshold < Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceIncreaseThreshold = -0.1 }, expectedErrs: []string{"'PrevalenceIncreaseThreshold' failed on the 'gte' tag"}},
			{name: "PrevalenceIncreaseThreshold > Range, PrevalenceDecreaseThreshold", config: func(cfg *Config) { cfg.Modifiers.PrevalenceIncreaseThreshold = 1.1 }, expectedErrs: []string{"'PrevalenceIncreaseThreshold' failed on the 'lte' tag", "'PrevalenceDecreaseThreshold' failed on the 'gtfield' tag"}},
			{name: "PrevalenceScoreDecrease < Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceScoreDecrease = -0.1 }, expectedErrs: []string{"'PrevalenceScoreDecrease' failed on the 'gte' tag"}},
			{name: "PrevalenceScoreDecrease > Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceScoreDecrease = 1.1 }, expectedErrs: []string{"'PrevalenceScoreDecrease' failed on the 'lte' tag"}},
			{name: "PrevalenceDecreaseThreshold < Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceDecreaseThreshold = -0.1 }, expectedErrs: []string{"'PrevalenceDecreaseThreshold' failed on the 'gte' tag"}},
			{name: "PrevalenceDecreaseThreshold > Range", config: func(cfg *Config) { cfg.Modifiers.PrevalenceDecreaseThreshold = 1.1 }, expectedErrs: []string{"'PrevalenceDecreaseThreshold' failed on the 'lte' tag"}},
			{name: "PrevalenceScoreDecreaseThreshold <= PrevalenceIncreaseThreshold", config: func(cfg *Config) { cfg.Modifiers.PrevalenceIncreaseThreshold = 1 }, expectedErrs: []string{"'PrevalenceDecreaseThreshold' failed on the 'gtfield' tag"}},
			{name: "FirstSeenScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenScoreIncrease = -0.1 }, expectedErrs: []string{"'FirstSeenScoreIncrease' failed on the 'gte' tag"}},
			{name: "FirstSeenScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenScoreIncrease = 1.1 }, expectedErrs: []string{"'FirstSeenScoreIncrease' failed on the 'lte' tag"}},
			{name: "FirstSeenIncreaseThreshold < Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenIncreaseThreshold = -0.1 }, expectedErrs: []string{"'FirstSeenIncreaseThreshold' failed on the 'gte' tag"}},
			{name: "FirstSeenIncreaseThreshold >= FirstSeenDecreaseThreshold", config: func(cfg *Config) { cfg.Modifiers.FirstSeenIncreaseThreshold = 31 }, expectedErrs: []string{"'FirstSeenDecreaseThreshold' failed on the 'gtfield' tag"}},
			{name: "FirstSeenScoreDecrease < Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenScoreDecrease = -0.1 }, expectedErrs: []string{"'FirstSeenScoreDecrease' failed on the 'gte' tag"}},
			{name: "FirstSeenScoreDecrease > Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenScoreDecrease = 1.1 }, expectedErrs: []string{"'FirstSeenScoreDecrease' failed on the 'lte' tag"}},
			{name: "FirstSeenDecreaseThreshold < Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenDecreaseThreshold = 0 }, expectedErrs: []string{"'FirstSeenDecreaseThreshold' failed on the 'gte' tag"}},
			{name: "FirstSeenDecreaseThreshold > Range", config: func(cfg *Config) { cfg.Modifiers.FirstSeenDecreaseThreshold = 91 }, expectedErrs: []string{"'FirstSeenDecreaseThreshold' failed on the 'lte' tag"}},
			{name: "FirstSeenDecreaseThreshold <= FirstSeenIncreaseThreshold", config: func(cfg *Config) { cfg.Modifiers.FirstSeenDecreaseThreshold = 1 }, expectedErrs: []string{"'FirstSeenDecreaseThreshold' failed on the 'gtfield' tag"}},
			{name: "MissingHostCountScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.MissingHostCountScoreIncrease = -0.1 }, expectedErrs: []string{"'MissingHostCountScoreIncrease' failed on the 'gte' tag"}},
			{name: "MissingHostCountScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.MissingHostCountScoreIncrease = 1.1 }, expectedErrs: []string{"'MissingHostCountScoreIncrease' failed on the 'lte' tag"}},
			{name: "RareSignatureScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.RareSignatureScoreIncrease = -0.1 }, expectedErrs: []string{"'RareSignatureScoreIncrease' failed on the 'gte' tag"}},
			{name: "RareSignatureScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.RareSignatureScoreIncrease = 1.1 }, expectedErrs: []string{"'RareSignatureScoreIncrease' failed on the 'lte' tag"}},
			{name: "C2OverDNSDirectConnScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.C2OverDNSDirectConnScoreIncrease = -0.1 }, expectedErrs: []string{"'C2OverDNSDirectConnScoreIncrease' failed on the 'gte' tag"}},
			{name: "C2OverDNSDirectConnScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.C2OverDNSDirectConnScoreIncrease = 1.1 }, expectedErrs: []string{"'C2OverDNSDirectConnScoreIncrease' failed on the 'lte' tag"}},
			{name: "MIMETypeMismatchScoreIncrease < Range", config: func(cfg *Config) { cfg.Modifiers.MIMETypeMismatchScoreIncrease = -0.1 }, expectedErrs: []string{"'MIMETypeMismatchScoreIncrease' failed on the 'gte' tag"}},
			{name: "MIMETypeMismatchScoreIncrease > Range", config: func(cfg *Config) { cfg.Modifiers.MIMETypeMismatchScoreIncrease = 1.1 }, expectedErrs: []string{"'MIMETypeMismatchScoreIncrease' failed on the 'lte' tag"}},
			{name: "Empty Struct", config: func(cfg *Config) { cfg.Modifiers = Modifiers{} }, expectedErrs: []string{"'Modifiers' failed on the 'required' tag"}},
		}},
	}
	for _, test := range tests {
		t.Run(test.group, func(t *testing.T) {
			for _, tc := range test.cases {
				t.Run(tc.name, func(t *testing.T) {
					// get default config
					cfg := GetDefaultConfig()

					// set env
					require.NoError(t, cfg.setEnv())

					// apply the test case config updates
					tc.config(&cfg)

					err := cfg.Validate()

					if len(tc.expectedErrs) == 0 {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						checkValidationErrs(t, tc.expectedErrs, err.Error())
					}

				})
			}
		})
	}
}

func TestConfig_ParseImpactCategoryScores(t *testing.T) {
	t.Run("Valid Categories", func(t *testing.T) {
		cfg := &Config{Scoring: Scoring{ThreatScoring: ThreatScoring{StrobeImpact: ScoreImpact{Category: HighThreat}, ThreatIntelImpact: ScoreImpact{Category: LowThreat}}}}
		require.NoError(t, cfg.parseImpactCategoryScores())
		require.InDelta(t, float32(HIGH_CATEGORY_SCORE), cfg.Scoring.StrobeImpact.Score, 0.0001, "StrobeImpact.Score should match expected value")
		require.InDelta(t, float32(LOW_CATEGORY_SCORE), cfg.Scoring.ThreatIntelImpact.Score, 0.0001, "ThreatIntelImpact.Score should match expected value")
	})

	t.Run("More Valid Categories", func(t *testing.T) {
		cfg := &Config{Scoring: Scoring{ThreatScoring: ThreatScoring{StrobeImpact: ScoreImpact{Category: MediumThreat}, ThreatIntelImpact: ScoreImpact{Category: NoneThreat}}}}
		require.NoError(t, cfg.parseImpactCategoryScores())
		require.InDelta(t, float32(MEDIUM_CATEGORY_SCORE), cfg.Scoring.StrobeImpact.Score, 0.0001, "StrobeImpact.Score should match expected value")
		require.InDelta(t, float32(NONE_CATEGORY_SCORE), cfg.Scoring.ThreatIntelImpact.Score, 0.0001, "ThreatIntelImpact.Score should match expected value")
	})

	t.Run("Invalid Category for StrobeImpact", func(t *testing.T) {
		cfg := &Config{Scoring: Scoring{ThreatScoring: ThreatScoring{StrobeImpact: ScoreImpact{Category: "unknown"}, ThreatIntelImpact: ScoreImpact{Category: LowThreat}}}}
		err := cfg.parseImpactCategoryScores()
		require.Error(t, err)
		require.Contains(t, err.Error(), errInvalidImpactCategory.Error())
	})

	t.Run("Invalid Category for ThreatIntelImpact", func(t *testing.T) {
		cfg := &Config{Scoring: Scoring{ThreatScoring: ThreatScoring{StrobeImpact: ScoreImpact{Category: HighThreat}, ThreatIntelImpact: ScoreImpact{Category: "invalid"}}}}
		err := cfg.parseImpactCategoryScores()
		require.Error(t, err)
		require.Contains(t, err.Error(), errInvalidImpactCategory.Error())
	})
}

func TestConfig_Reset(t *testing.T) {

	testCases := []struct {
		name        string
		cfg         *Config
		expectedErr bool
	}{
		{
			name: "Valid Confgig - No Env Changes",
			cfg: func() *Config {
				cfg := GetDefaultConfig()
				require.NoError(t, cfg.setEnv())
				cfg.RITA = RITA{false, 25000, 1, 1, ThreatIntel{[]string{"https://chickenstrip.com"}}}
				cfg.Filtering.InternalSubnets = []util.Subnet{util.NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(8+96, 128)})}
				cfg.Filtering.FilterExternalToInternal = false
				cfg.Scoring.Beacon = BeaconScoring{4, 0.6, 0.1, 0.1, 0.2, 1, 1, 0, 0, 3, ScoreThresholds{0, 1, 2, 3}}
				cfg.Scoring.LongConnectionScoreThresholds = ScoreThresholds{1, 2, 3, 4}
				cfg.Scoring.C2ScoreThresholds = ScoreThresholds{1, 2, 3, 4}
				cfg.Scoring.StrobeImpact = ScoreImpact{Category: LowThreat, Score: LOW_CATEGORY_SCORE}
				cfg.Scoring.ThreatIntelImpact = ScoreImpact{Category: LowThreat, Score: LOW_CATEGORY_SCORE}
				cfg.Modifiers = Modifiers{0, 1, 0, 0, 0, 0.1, 0, 1, 0, 1.1, 0, 0, 0, 0}
				require.NoError(t, cfg.Validate())
				return &cfg
			}(),
		},
		{
			name: "Invalid Config - No Env Changes",
			cfg: func() *Config {
				cfg := GetDefaultConfig()
				require.NoError(t, cfg.setEnv())
				cfg.RITA = RITA{false, 0, 0, 0, ThreatIntel{[]string{"invalid"}}}
				cfg.Filtering = Filtering{}
				cfg.Scoring.Beacon = BeaconScoring{1, 0.5, 0.5, 0.5, 0.5, 1, 1, 0.5, 1, 1, ScoreThresholds{-1, -2, -3, -4}}
				return &cfg
			}(),
		},
		{
			name: "Valid Config - Valid Env Changes",
			cfg: func() *Config {
				cfg := GetDefaultConfig()
				require.NoError(t, cfg.setEnv())
				cfg.Env.DBConnection = "chickenstrip:9999"
				cfg.Env.LogLevel = 6
				cfg.RITA = RITA{false, 25000, 1, 1, ThreatIntel{[]string{"https://chickenstrip.com"}}}
				cfg.Filtering.InternalSubnets = []util.Subnet{util.NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(8+96, 128)})}
				cfg.Filtering.FilterExternalToInternal = false
				require.NoError(t, cfg.Validate())
				return &cfg
			}(),
		},
		{
			name: "Invalid Config - Invalid Env Changes",
			cfg: func() *Config {
				cfg := GetDefaultConfig()
				require.NoError(t, cfg.setEnv())
				cfg.Env.DBConnection = "invalid"
				cfg.Env.LogLevel = 10
				cfg.RITA = RITA{false, 25000, 1, 1, ThreatIntel{[]string{"https://chickenstrip.com"}}}
				cfg.Filtering.InternalSubnets = []util.Subnet{util.NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(8+96, 128)})}
				cfg.Filtering.FilterExternalToInternal = false
				return &cfg
			}(),
			expectedErr: true,
		},
		{
			name: "Invalid Config - Valid Env Changes",
			cfg: func() *Config {
				cfg := GetDefaultConfig()
				require.NoError(t, cfg.setEnv())
				cfg.Env.DBConnection = "chickenstrip:9999"
				cfg.Env.LogLevel = 6
				cfg.RITA = RITA{false, 0, 0, 0, ThreatIntel{[]string{"invalid"}}}
				cfg.Filtering = Filtering{}
				cfg.Scoring.Beacon = BeaconScoring{1, 0.5, 0.5, 0.5, 0.5, 1, 1, 0.5, 1, 1, ScoreThresholds{-1, -2, -3, -4}}
				return &cfg
			}(),
		},
		{
			name: "Empty Except for Env",
			cfg: func() *Config {
				cfg := &Config{}
				require.NoError(t, cfg.setEnv())
				cfg.Env.DBConnection = "chickenstrip:9999"
				cfg.Env.LogLevel = 6
				return cfg
			}(),
		},
		{
			name:        "Empty Struct",
			cfg:         &Config{},
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// get default config
			origConfig := GetDefaultConfig()
			require.NoError(t, origConfig.setEnv())

			// get the modified test config
			cfg := *tc.cfg

			// store environment variables from the modified config
			env := cfg.Env

			// reset the config
			err := cfg.Reset()
			if tc.expectedErr {
				require.Error(t, err, "resetting config should produce an error")
			} else {
				require.NoError(t, err, "resetting config should not produce an error")

				// verify that if the environment variables were changed, there were NOT reset
				if env != origConfig.Env {
					require.Equal(t, env, cfg.Env, "env should not have been reset")
					require.NotEqual(t, origConfig.Env, cfg.Env, "env should not match default config")

					// set orig config env to modified so we can just do a straight comparison on the structs below, since
					// all other fields should be the same
					origConfig.Env = env
				}

				// verify that fields were reset to default values
				require.Equal(t, origConfig, cfg, "config should match default config")

				// verify the config
				err = cfg.Validate()
				require.NoError(t, err, "validating config should not produce an error")
			}
		})
	}
}

func TestGetDefaultConfig(t *testing.T) {
	// get a copy of the default config variable that function is supposed to return
	origConfigVar := defaultConfig()

	// create *Config object from the default config variable
	origCfg := &origConfigVar

	// set the environment variables
	require.NoError(t, origCfg.setEnv())

	// validate
	require.NoError(t, origCfg.Validate(), "config should be valid")

	// get the default config object from the function
	cfg := GetDefaultConfig()
	require.NotNil(t, cfg, "config should not be nil")

	// set env variables
	require.NoError(t, cfg.setEnv())

	// validate
	require.NoError(t, cfg.Validate(), "config should be valid")

	// verify version got set (gets set in function if it wasn't set already)
	require.Equal(t, "dev", Version, "version should be 'dev'")

	// verify the acquired config is the same as the default config variable
	require.Equal(t, origCfg, &cfg, "config should match expected value")
}

func TestValidateScoreThresholdsRange(t *testing.T) {
	tests := []struct {
		name          string
		thresholds    ScoreThresholds
		min           int32
		max           int32
		expectedError bool
	}{
		{
			name:          "valid thresholds, (0 - 10)",
			thresholds:    ScoreThresholds{Base: 0, Low: 1, Med: 2, High: 3},
			min:           0,
			max:           10,
			expectedError: false,
		},
		{
			name:          "valid beacon thresholds, (0 - 100)",
			thresholds:    ScoreThresholds{Base: 50, Low: 75, Med: 90, High: 100},
			min:           0,
			max:           100,
			expectedError: false,
		},
		{
			name:          "valid long conn thresholds, (0 - 24*3600)",
			thresholds:    ScoreThresholds{Base: 3600, Low: 4 * 3600, Med: 8 * 3600, High: 12 * 3600},
			min:           0,
			max:           24 * 3600,
			expectedError: false,
		},
		{
			name:          "valid c2 thresholds, (0 - no max)",
			thresholds:    ScoreThresholds{Base: 100, Low: 500, Med: 800, High: 1000},
			min:           0,
			max:           -1,
			expectedError: false,
		},
		{
			name:          "invalid thresholds (out of range - max)",
			thresholds:    ScoreThresholds{Base: 0, Low: 1, Med: 2, High: 3},
			min:           0,
			max:           2,
			expectedError: true,
		},
		{
			name:          "invalid thresholds (out of range - min)",
			thresholds:    ScoreThresholds{Base: 0, Low: 1, Med: 2, High: 3},
			min:           1,
			max:           10,
			expectedError: true,
		},
		// note: score thresholds being in increasing order and unique is validated by the ltfield tags in the struct
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			err := validateScoreThresholdsRange(test.thresholds, test.min, test.max)
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)
		})
	}
}

func TestValidateImpactCategory(t *testing.T) {
	tests := []struct {
		name          string
		impact        ImpactCategory
		expectedError bool
	}{
		{
			name:          "high impact category",
			impact:        "high",
			expectedError: false,
		},
		{
			name:          "none impact category",
			impact:        "none",
			expectedError: false,
		},
		{
			name:          "invalid impact category",
			impact:        "iaminvalid",
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			err := ValidateImpactCategory(test.impact)
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)
		})
	}
}

func TestGetScoreFromImpactCategory(t *testing.T) {
	tests := []struct {
		name          string
		impact        ImpactCategory
		expectedScore float32
		expectedError error
	}{
		{
			name:          "high impact category",
			impact:        "high",
			expectedScore: HIGH_CATEGORY_SCORE,
			expectedError: nil,
		},
		{
			name:          "medium impact category",
			impact:        "medium",
			expectedScore: MEDIUM_CATEGORY_SCORE,
			expectedError: nil,
		},
		{
			name:          "low impact category",
			impact:        "low",
			expectedScore: LOW_CATEGORY_SCORE,
			expectedError: nil,
		},
		{
			name:          "none impact category",
			impact:        "none",
			expectedScore: NONE_CATEGORY_SCORE,
			expectedError: nil,
		},
		{
			name:          "invalid impact category",
			impact:        "iaminvalid",
			expectedScore: 0,
			expectedError: errInvalidImpactCategory,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			score, err := GetScoreFromImpactCategory(test.impact)
			require.Equal(test.expectedError, err, "error should match expected value")
			require.InDelta(test.expectedScore, score, 0.0001, "score should match expected value")
		})
	}
}

func TestGetImpactCategoryFromScore(t *testing.T) {
	tests := []struct {
		name           string
		score          float64
		expectedImpact ImpactCategory
	}{
		{
			name: "High Category Score",
			// score > MEDIUM_CATEGORY_SCORE
			score:          HIGH_CATEGORY_SCORE,
			expectedImpact: HighThreat,
		},
		{
			name: "Medium Category Score",
			// score > LOW_CATEGORY_SCORE && score <= MEDIUM_CATEGORY_SCORE
			score:          MEDIUM_CATEGORY_SCORE,
			expectedImpact: MediumThreat,
		},
		{
			name: "Low Category Score",
			// score > NONE_CATEGORY_SCORE && score <= LOW_CATEGORY_SCORE
			score:          LOW_CATEGORY_SCORE,
			expectedImpact: LowThreat,
		},
		{
			name: "None Category Score",
			// score <= NONE_CATEGORY_SCORE
			score:          NONE_CATEGORY_SCORE,
			expectedImpact: NoneThreat,
		},
		{
			name:           "Invalid Score",
			score:          -1,
			expectedImpact: NoneThreat,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			impact := GetImpactCategoryFromScore(test.score)
			require.Equal(test.expectedImpact, impact, "Expected impact to be %v, got %v", test.expectedImpact, impact)
		})
	}
}

func TestScoreThresholds_ToMap(t *testing.T) {
	tests := []struct {
		name     string
		input    ScoreThresholds
		expected map[string]int32
	}{
		{
			name:     "Valid Values",
			input:    ScoreThresholds{Base: 10, Low: 20, Med: 30, High: 40},
			expected: map[string]int32{"base": 10, "low": 20, "med": 30, "high": 40},
		},
		{
			name:     "Zero Values",
			input:    ScoreThresholds{Base: 0, Low: 0, Med: 0, High: 0},
			expected: map[string]int32{"base": 0, "low": 0, "med": 0, "high": 0},
		},
		{
			name:     "Empty Struct",
			input:    ScoreThresholds{},
			expected: map[string]int32{"base": 0, "low": 0, "med": 0, "high": 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.input.ToMap()
			require.Equal(t, test.expected, result)
		})
	}
}

func TestScoreImpact_String(t *testing.T) {
	tests := []struct {
		name     string
		input    ScoreImpact
		expected string
	}{
		{
			name:     "Valid ImpactCategory",
			input:    ScoreImpact{Category: HighThreat},
			expected: string(HighThreat),
		},
		{
			name:     "Empty ImpactCategory",
			input:    ScoreImpact{Category: ImpactCategory("")},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.input.String()
			require.Equal(t, test.expected, result)
		})
	}
}

func TestScoreImpact_Scan(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		expected  ScoreImpact
		expectErr error
	}{
		{
			name:     "Valid Impact Category",
			input:    string(HighThreat),
			expected: ScoreImpact{Category: HighThreat, Score: HIGH_CATEGORY_SCORE},
		},
		{
			name:      "Invalid Impact Category",
			input:     "invalid",
			expectErr: errInvalidImpactCategory,
		},
		{
			name:      "Empty Impact Category",
			input:     "",
			expectErr: errInvalidImpactCategory,
		},
		{
			name:      "Invalid Non-string Input",
			input:     123,
			expectErr: fmt.Errorf("cannot scan int into ScoreImpact"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result ScoreImpact
			err := result.Scan(test.input)
			if test.expectErr != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, result)
			}
		})
	}
}

func checkValidationErrs(t *testing.T, errs []string, response string) {
	t.Helper()

	require.NotEmpty(t, response, "error response should not be empty")

	// split the response by newlines
	responseErrs := strings.Split(response, "\n")

	// remove any empty strings
	responseErrs = slices.DeleteFunc(responseErrs, func(val string) bool { return val == "" })

	require.Len(t, responseErrs, len(errs))

	for _, err := range errs {
		require.Contains(t, response, err)
	}
}
