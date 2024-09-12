package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/activecm/rita/v5/util"
	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
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

func TestReadFile(t *testing.T) {
	afs := afero.NewOsFs()
	fileContents, err := readFile(afs, defaultConfigPath)
	require.NoError(t, err)
	assert.NotEmpty(t, fileContents)
}

func TestReadFileConfig(t *testing.T) {

	tests := []struct {
		name           string
		configJSON     string
		expectedConfig *Config
		expectedError  bool
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
				require.NoError(t, setEnv(cfg))
				return cfg
			}(),
		},
		{
			name:       "Empty Config",
			configJSON: `{}`,
			expectedConfig: func() *Config {
				cfg := defaultConfig()
				require.NoError(t, setEnv(&cfg))
				return &cfg
			}(),
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// create mock file system in memory
			afs := afero.NewMemMapFs()

			// get config file path
			configPath := fmt.Sprintf("test-config-%d.hjson", i)

			// create file
			require.NoError(t, afero.WriteFile(afs, configPath, []byte(test.configJSON), 0o775))
			defer func() { require.NoError(t, afs.Remove(configPath)) }()

			// call function
			cfg, err := ReadFileConfig(afs, configPath)

			if test.expectedError {
				require.Error(t, err, "expected error when reading file config")
			} else {
				require.NoError(t, err, "expected no error when reading file config, got err=%v", err)
				require.NotNil(t, cfg, "expected config to be non-nil")

				// verify version got set
				require.Equal(t, "dev", Version, "version should be 'dev'")
			}

			// verify that env variables are not overwritten by JSON
			require.Equal(t, test.expectedConfig.Env, cfg.Env, "Env should match expected value")

			// verify that the retrived config matches the expected config (split up for easier debugging)
			require.Equal(t, test.expectedConfig.RITA, cfg.RITA, "RITA should match expected value")
			require.Equal(t, test.expectedConfig.Filtering, cfg.Filtering, "Filtering should match expected value")
			require.Equal(t, test.expectedConfig.Scoring, cfg.Scoring, "Scoring should match expected value")
			require.Equal(t, test.expectedConfig.Modifiers, cfg.Modifiers, "Modifiers should match expected value")

			// all together
			require.Equal(t, test.expectedConfig, cfg, "config should match expected value")
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
			{name: "DBConnection Empty", config: func(cfg *Config) { cfg.Env.DBConnection = "" }, expectedErrs: []string{"'DBConnection' failed on the 'required' tag"}},
			{name: "HTTPExtensionsFilePath Not Path", config: func(cfg *Config) { cfg.Env.HTTPExtensionsFilePath = "--" }, expectedErrs: []string{"'HTTPExtensionsFilePath' failed on the 'file' tag"}},
			{name: "HTTPExtensionsFilePath Empty", config: func(cfg *Config) { cfg.Env.HTTPExtensionsFilePath = "" }, expectedErrs: []string{"'HTTPExtensionsFilePath' failed on the 'required' tag"}},
			{name: "Missing All Required", config: func(cfg *Config) { cfg.Env = Env{} }, expectedErrs: []string{"'DBConnection' failed on the 'required' tag", "'HTTPExtensionsFilePath' failed on the 'required' tag"}},
		}},
		{"RITA", []testCase{
			{name: "BatchSize < Range", config: func(cfg *Config) { cfg.RITA.BatchSize = 24999 }, expectedErrs: []string{"'BatchSize' failed on the 'gte' tag"}},
			{name: "BatchSize > Range", config: func(cfg *Config) { cfg.RITA.BatchSize = 2000001 }, expectedErrs: []string{"'BatchSize' failed on the 'lte' tag"}},
			{name: "MaxQueryExecutionTime < Range", config: func(cfg *Config) { cfg.RITA.MaxQueryExecutionTime = 0 }, expectedErrs: []string{"'MaxQueryExecutionTime' failed on the 'gte' tag"}},
			{name: "MaxQueryExecutionTime > Range", config: func(cfg *Config) { cfg.RITA.MaxQueryExecutionTime = 2000001 }, expectedErrs: []string{"'MaxQueryExecutionTime' failed on the 'lte' tag"}},
			{name: "MonthsToKeepHistoricalFirstSeen < Range", config: func(cfg *Config) { cfg.RITA.MonthsToKeepHistoricalFirstSeen = 0 }, expectedErrs: []string{"'MonthsToKeepHistoricalFirstSeen' failed on the 'gte' tag"}},
			{name: "MonthsToKeepHistoricalFirstSeen > Range", config: func(cfg *Config) { cfg.RITA.MonthsToKeepHistoricalFirstSeen = 61 }, expectedErrs: []string{"'MonthsToKeepHistoricalFirstSeen' failed on the 'lte' tag"}},
			{name: "ThreatIntel.OnlineFeeds Not URLs", config: func(cfg *Config) { cfg.RITA.ThreatIntel.OnlineFeeds = []string{"invalid"} }, expectedErrs: []string{"'OnlineFeeds[0]' failed on the 'url' tag"}},
			// TODO: log level?  TODO: see question above CustomFeedsDirectory filed in config.go {name: "CustomFeedsDirectory Not Path"},
			{name: "Missing All Required", config: func(cfg *Config) { cfg.RITA = RITA{} }, expectedErrs: []string{"'BatchSize' failed on the 'gte' tag", "'MaxQueryExecutionTime' failed on the 'gte' tag", "'MonthsToKeepHistoricalFirstSeen' failed on the 'gte' tag", "'CustomFeedsDirectory' failed on the 'required' tag"}},
		}},
		{"Filtering", []testCase{
			// {name: "InternalSubnets Empty", config: func(cfg *Config) { cfg.Filtering.InternalSubnets = []util.Subnet{} }, expectedErrs: []string{"'InternalSubnets' failed on the 'internal_subnets' tag"}},
			{name: "AlwaysIncludedDomains Not Domains", config: func(cfg *Config) { cfg.Filtering.AlwaysIncludedDomains = []string{"notadomain"} }, expectedErrs: []string{"'AlwaysIncludedDomains[0]' failed on the 'fqdn' tag"}},
			{name: "AlwaysIncludedDomains Mixed Validity", config: func(cfg *Config) { cfg.Filtering.AlwaysIncludedDomains = []string{"valid.com", "notadomain"} }, expectedErrs: []string{"'AlwaysIncludedDomains[1]' failed on the 'fqdn' tag"}},
			{name: "NeverIncludedDomains Not Domains", config: func(cfg *Config) { cfg.Filtering.NeverIncludedDomains = []string{"notadomain"} }, expectedErrs: []string{"'NeverIncludedDomains[0]' failed on the 'fqdn' tag"}},
			{name: "NeverIncludedDomains Mixed Validity", config: func(cfg *Config) { cfg.Filtering.NeverIncludedDomains = []string{"valid.com", "notadomain"} }, expectedErrs: []string{"'NeverIncludedDomains[1]' failed on the 'fqdn' tag"}},
		}},
		{"Beacon Scoring", []testCase{
			{name: "UniqueConnectionThreshold < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.UniqueConnectionThreshold = 3 }, expectedErrs: []string{"'UniqueConnectionThreshold' failed on the 'gte' tag"}},
			{name: "Score Weight Sum != 1", config: func(cfg *Config) { cfg.Scoring.Beacon.TimestampScoreWeight = 1 }, expectedErrs: []string{"'Beacon' failed on the 'beacon_scoring' tag"}},
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
			{name: "DurationMinHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationMinHoursSeen = 0 }, expectedErrs: []string{"'DurationMinHoursSeen' failed on the 'gte' tag"}},
			{name: "DurationConsistencyIdealHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.DurationConsistencyIdealHoursSeen = 0 }, expectedErrs: []string{"'DurationConsistencyIdealHoursSeen' failed on the 'gte' tag"}},
			{name: "HistogramModeSensitivity < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramModeSensitivity = -1 }, expectedErrs: []string{"'HistogramModeSensitivity' failed on the 'gte' tag"}},
			{name: "HistogramModeSensitivity > Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramModeSensitivity = 100 }, expectedErrs: []string{"'HistogramModeSensitivity' failed on the 'lte' tag"}},
			{name: "HistogramBimodalOutlierRemoval < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalOutlierRemoval = -1 }, expectedErrs: []string{"'HistogramBimodalOutlierRemoval' failed on the 'gte' tag"}},
			{name: "HistogramBimodalMinHoursSeen < Range", config: func(cfg *Config) { cfg.Scoring.Beacon.HistogramBimodalMinHoursSeen = 0 }, expectedErrs: []string{"'HistogramBimodalMinHoursSeen' failed on the 'gte' tag"}},
			{name: "ScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds.Base = -1 }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds High > Max", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds.High = 101 }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Base == Low", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{75, 75, 90, 100} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Base > Low", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{76, 75, 90, 100} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Low > Med", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 91, 90, 100} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Low == Med", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 90, 90, 100} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Med > High", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 75, 91, 90} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "ScoreThresholds Med == High", config: func(cfg *Config) { cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{50, 75, 90, 90} }, expectedErrs: []string{"'ScoreThresholds' failed on the 'score_thresholds' tag"}},
		}},
		{"Threat Scoring", []testCase{
			{name: "LongConnectionScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds.Base = 0 }, expectedErrs: []string{"'LongConnectionScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "LongConnectionScoreThresholds High > Max", config: func(cfg *Config) { cfg.Scoring.LongConnectionScoreThresholds.High = (24 * 3600) + 1 }, expectedErrs: []string{"'LongConnectionScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "C2ScoreThresholds Base < Min", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds.Base = 0 }, expectedErrs: []string{"'C2ScoreThresholds' failed on the 'score_thresholds' tag"}},
			{name: "C2ScoreThresholds High Should Be Unlimited", config: func(cfg *Config) { cfg.Scoring.C2ScoreThresholds.High = 2147483647 }}, // max int32
			{name: "StrobeImpact Category Invalid", config: func(cfg *Config) { cfg.Scoring.StrobeImpact.Category = "invalid" }, expectedErrs: []string{"'StrobeImpact' failed on the 'impact_category' tag"}},
			{name: "ThreatIntelImpact Category Invalid", config: func(cfg *Config) { cfg.Scoring.ThreatIntelImpact.Category = "invalid" }, expectedErrs: []string{"'ThreatIntelImpact' failed on the 'impact_category' tag"}},
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
			{name: "All Required Missing", config: func(cfg *Config) { cfg.Modifiers = Modifiers{} }, expectedErrs: []string{"'ThreatIntelScoreIncrease' failed on the 'required' tag", "'ThreatIntelDataSizeThreshold' failed on the 'required' tag", "'PrevalenceScoreIncrease' failed on the 'required' tag", "'PrevalenceIncreaseThreshold' failed on the 'required' tag", "'PrevalenceScoreDecrease' failed on the 'required' tag", "'PrevalenceDecreaseThreshold' failed on the 'required' tag", "'FirstSeenScoreIncrease' failed on the 'required' tag", "'FirstSeenIncreaseThreshold' failed on the 'required' tag", "'FirstSeenScoreDecrease' failed on the 'required' tag", "'FirstSeenDecreaseThreshold' failed on the 'required' tag", "'MissingHostCountScoreIncrease' failed on the 'required' tag", "'RareSignatureScoreIncrease' failed on the 'required' tag", "'C2OverDNSDirectConnScoreIncrease' failed on the 'required' tag", "'MIMETypeMismatchScoreIncrease' failed on the 'required' tag"}},
		}},
	}
	for _, test := range tests {
		t.Run(test.group, func(t *testing.T) {
			for _, tc := range test.cases {
				t.Run(tc.name, func(t *testing.T) {
					// get default config
					cfg, err := GetDefaultConfig()
					require.NoError(t, err)

					// set env
					require.NoError(t, setEnv(&cfg))

					// apply the test case config updates
					tc.config(&cfg)

					err = cfg.Validate()

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
	// 	require := require.New(t)

	// get default config
	origConfig, err := GetDefaultConfig()
	require.NoError(t, err)

	// create a copy of the config and modify it with invalid values
	cfg := origConfig
	cfg.Env.DBConnection = "chickenstrip"
	cfg.Scoring.Beacon = BeaconScoring{1, 0.5, 0.5, 0.5, 0.5, 1, 1, 0.5, 1, 1, ScoreThresholds{-1, -2, -3, -4}}

	// verify that the values are not the same before resetting
	require.NotEqual(t, origConfig, cfg, "config should not match default config")

	// reset the config
	err = cfg.Reset()
	require.NoError(t, err, "resetting config should not produce an error")

	// verify that the values have been reset
	require.Equal(t, origConfig, cfg, "config should match expected value")

	// verify the config
	err = cfg.Validate()
	require.NoError(t, err, "validating config should not produce an error")
}

func TestGetDefaultConfig(t *testing.T) {
	// get a copy of the default config variable that function is supposed to return
	origConfigVar := defaultConfig()

	// set fields that are environment dependent in original config variable
	origConfigVar.Env.DBConnection = os.Getenv("DB_ADDRESS")
	configDir, err := filepath.Abs(os.Getenv("CONFIG_DIR"))
	require.NoError(t, err)
	origConfigVar.Env.HTTPExtensionsFilePath = filepath.Join(configDir, "http_extensions_list.csv")

	// get the default config object from the function
	cfg, err := GetDefaultConfig()
	require.NoError(t, err, "getDefaultConfig should not produce an error")
	require.NotNil(t, cfg, "config should not be nil")

	// verify version got set (gets set in function if it wasn't set already)
	require.Equal(t, "dev", Version, "version should be 'dev'")

	// verify the acquired config is the same as the default config variable
	require.Equal(t, origConfigVar, cfg, "config should match expected value")
}

func TestValidateScoreThresholds(t *testing.T) {
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
			name:          "invalid thresholds (not in ascending order)",
			thresholds:    ScoreThresholds{Base: 0, Low: 2, Med: 1, High: 3},
			min:           0,
			max:           10,
			expectedError: true,
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
		{
			name:          "invalid thresholds (two thresholds equal)",
			thresholds:    ScoreThresholds{Base: 0, Low: 1, Med: 1, High: 3},
			min:           0,
			max:           10,
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			err := validateScoreThresholds(test.thresholds, test.min, test.max)
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
		score          float32
		expectedImpact ImpactCategory
		expectedError  bool
	}{
		{
			name: "high impact category",
			// score > MEDIUM_CATEGORY_SCORE
			score:          HIGH_CATEGORY_SCORE,
			expectedImpact: "high",
		},
		{
			name: "medium impact category",
			// score > LOW_CATEGORY_SCORE && score <= MEDIUM_CATEGORY_SCORE
			score:          MEDIUM_CATEGORY_SCORE,
			expectedImpact: "medium",
		},
		{
			name: "low impact category",
			// score > NONE_CATEGORY_SCORE && score <= LOW_CATEGORY_SCORE
			score:          LOW_CATEGORY_SCORE,
			expectedImpact: "low",
		},
		{
			name: "none impact category",
			// score <= NONE_CATEGORY_SCORE
			score:          NONE_CATEGORY_SCORE,
			expectedImpact: "none",
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

func checkValidationErrs(t *testing.T, errs []string, response string) {
	t.Helper()

	// split the response by newlines
	responseErrs := strings.Split(response, "\n")

	// remove any empty strings
	responseErrs = slices.DeleteFunc(responseErrs, func(val string) bool { return val == "" })

	require.Len(t, responseErrs, len(errs))

	for _, err := range errs {
		require.Contains(t, response, err)
	}
}
