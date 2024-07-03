package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/activecm/ritav2/util"

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

func TestLoadConfig(t *testing.T) {
	afs := afero.NewOsFs()

	// load the default config file
	cfg, err := LoadConfig(afs, defaultConfigPath)
	require.NoError(t, err, "should be able to load the default config file")

	err = cfg.Validate()
	require.NoError(t, err, "the loaded default config file should be valid")

	cfg, err = GetConfig()
	require.NoError(t, err, "should be able to get the config file after it has been loaded")

	err = cfg.Validate()
	require.NoError(t, err, "the config returned from GetConfig should be valid")
}

func TestReadFile(t *testing.T) {
	afs := afero.NewOsFs()
	fileContents, err := readFile(afs, defaultConfigPath)
	require.NoError(t, err)
	assert.NotEmpty(t, fileContents)
}

func TestParseJSON(t *testing.T) {

	tests := []struct {
		name           string
		config         []byte
		expectedConfig Config
		expectedError  error
	}{
		{
			name: "valid config",
			config: []byte(`
			{
				db_connection: "localhost:9000",
				update_check_enabled: false,
				filtering: {
					internal_subnets: ["11.0.0.0/8", "120.130.140.150/8"],
					always_included_subnets: ["13.0.0.0/8", "160.140.150.160/8"],
					never_included_subnets: ["12.0.0.0/8", "150.140.150.160/8"],
					always_included_domains: ["abc.com", "def.com"],
					never_included_domains: ["ghi.com", "jkl.com"],
					filter_external_to_internal: false,
				},
				http_extensions_file_path: "/path/to/http/extensions",
				batch_size: 75000,
				max_query_execution_time: 120000,
				months_to_keep_historical_first_seen: 6,
				threat_intel: {
					online_feeds: ["https://example.com/feed1", "https://example.com/feed2"],
					custom_feeds_directory: "/path/to/custom/feeds",
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
					long_connection_minimum_duration: 10,
					long_connection_score_thresholds: {
						base: 0,
						low: 1,
						medium: 2,
						high: 3
					},
					c2_subdomain_threshold: 10,
					c2_score_thresholds: {
						base: 0,
						low: 1,
						medium: 2,
						high: 3
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
				log_level: 3,
				logging_enabled: false,
			}
			`),
			expectedConfig: Config{
				UpdateCheckEnabled: false,
				Filter: Filter{
					InternalSubnetsJSON: []string{"11.0.0.0/8", "120.130.140.150/8"},
					InternalSubnets: []*net.IPNet{
						{IP: net.IP{11, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{120, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
					},
					AlwaysIncludedSubnetsJSON: []string{"13.0.0.0/8", "160.140.150.160/8"},
					AlwaysIncludedSubnets: []*net.IPNet{
						{IP: net.IP{13, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{160, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
					},
					// mandatoryNeverIncludeSubnets are always apended to any neverIncludedSubnet entries
					NeverIncludedSubnetsJSON: append([]string{"12.0.0.0/8", "150.140.150.160/8"}, getMandatoryNeverIncludeSubnets()...),
					NeverIncludedSubnets: []*net.IPNet{
						{IP: net.IP{12, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{150, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{0, 0, 0, 0}, Mask: net.IPMask{255, 255, 255, 255}},
						{IP: net.IP{127, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{169, 254, 0, 0}, Mask: net.IPMask{255, 255, 0, 0}},
						{IP: net.IP{224, 0, 0, 0}, Mask: net.IPMask{240, 0, 0, 0}},
						{IP: net.IP{255, 255, 255, 255}, Mask: net.IPMask{255, 255, 255, 255}},
						{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
						{IP: net.IPv6unspecified, Mask: net.CIDRMask(128, 128)},
						{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},
						{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)},
						{IP: net.ParseIP("ff02::2"), Mask: net.CIDRMask(128, 128)},
					},

					AlwaysIncludedDomains:    []string{"abc.com", "def.com"},
					NeverIncludedDomains:     []string{"ghi.com", "jkl.com"},
					FilterExternalToInternal: false,
				},
				HTTPExtensionsFilePath:          "/path/to/http/extensions",
				BatchSize:                       75000,
				MaxQueryExecutionTime:           120000,
				MonthsToKeepHistoricalFirstSeen: 6,
				Scoring: Scoring{
					Beacon: Beacon{
						UniqueConnectionThreshold:       10,
						TsWeight:                        0.35,
						DsWeight:                        0.20,
						DurWeight:                       0.35,
						HistWeight:                      0.10,
						DurMinHours:                     10,
						DurIdealNumberOfConsistentHours: 15,
						HistModeSensitivity:             0.08,
						HistBimodalOutlierRemoval:       2,
						HistBimodalMinHours:             15,
						ScoreThresholds: ScoreThresholds{
							Base: 0,
							Low:  1,
							Med:  2,
							High: 3,
						},
					},
					LongConnectionMinimumDuration: 10,
					LongConnectionScoreThresholds: ScoreThresholds{
						Base: 0,
						Low:  1,
						Med:  2,
						High: 3,
					},
					C2SubdomainThreshold: 10,
					C2ScoreThresholds: ScoreThresholds{
						Base: 0,
						Low:  1,
						Med:  2,
						High: 3,
					},
					StrobeImpact: ScoreImpact{
						Category: LowThreat,
						Score:    LOW_CATEGORY_SCORE,
					},
					ThreatIntelImpact: ScoreImpact{
						Category: LowThreat,
						Score:    LOW_CATEGORY_SCORE,
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
				ThreatIntel: ThreatIntel{
					OnlineFeeds:          []string{"https://example.com/feed1", "https://example.com/feed2"},
					CustomFeedsDirectory: "/path/to/custom/feeds",
				},
				LogLevel:       3,
				LoggingEnabled: false,
			},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// set up default config
			cfg, err := getDefaultConfig()
			require.NoError(err, "loading default config should not produce an error")

			// parse JSON
			err = cfg.parseJSON(test.config)

			// if err == nil && !test.expectedError {
			// 	expectedVal := reflect.ValueOf(test.expectedConfig)
			// 	actualVal := reflect.ValueOf(cfg)
			// 	for i := 0; i < expectedVal.NumField(); i++ {
			// 		expectedField := expectedVal.Field(i)
			// 		actualField := actualVal.Field(i)
			// 		fmt.Println("expectedField: ", expectedField.Interface(), "actualField: ", actualField.Interface())
			// if !reflect.DeepEqual(expectedField.Interface(), actualField.Interface()) {
			// 	t.Errorf("Field mismatch in %s: expected %v, got %v",
			// 		expectedVal.Type().Field(i).Name,
			// 		expectedField.Interface(),
			// 		actualField.Interface())
			// }
			// 	}
			// }

			// if test.expectedError {
			// 	require.Error(err, "parseJSON should have produced an error")
			// } else {
			// 	require.NoError(err, "parseJSON should not produce an error")
			// // Compare all fields using reflection
			// if !reflect.DeepEqual(cfg, test.expectedConfig) {
			// 	t.Errorf("Config fields do not match. Got %+v, expected %+v", cfg, test.expectedConfig)
			// }
			// elemCfg := reflect.ValueOf(cfg)
			// elemExpected := reflect.ValueOf(test.expectedConfig)
			// for i := 0; i < elemCfg.NumField(); i++ {
			// 	cfgField := elemCfg.Field(i)
			// 	expectedField := elemExpected.Field(i)

			// 	if !reflect.DeepEqual(cfgField.Interface(), expectedField.Interface()) {
			// 		t.Errorf("Field '%s' mismatch: got %+v, want %+v", elemCfg.Type().Field(i).Name, cfgField.Interface(), expectedField.Interface())
			// 	}
			// }
			// }

			// check if an error was expected
			require.Equal(test.expectedError, err, "error should match expected value")

			// verify that env variables are not overwritten by JSON
			// load environment variables with panic prevention
			err = godotenv.Overload("../.env", "../integration/test.env")
			require.NoError(err, "loading environment variables should not produce an error")
			// get the database connection string
			connection := os.Getenv("DB_ADDRESS")
			require.Equal(connection, cfg.DBConnection, "DBConnection should not be overwritten by JSON and should match the env variable")

			// check for proper parsing
			require.Equal(test.expectedConfig.UpdateCheckEnabled, cfg.UpdateCheckEnabled, "UpdateCheckEnabled should match expected value")

			require.ElementsMatch(test.expectedConfig.Filter.InternalSubnetsJSON, cfg.Filter.InternalSubnetsJSON, "InternalSubnetsJSON should match expected value")
			require.ElementsMatch(test.expectedConfig.Filter.InternalSubnets, cfg.Filter.InternalSubnets, "InternalSubnets should match expected value")

			require.ElementsMatch(test.expectedConfig.Filter.AlwaysIncludedSubnetsJSON, cfg.Filter.AlwaysIncludedSubnetsJSON, "AlwaysIncludedSubnetsJSON should match expected value")
			require.ElementsMatch(test.expectedConfig.Filter.AlwaysIncludedSubnets, cfg.Filter.AlwaysIncludedSubnets, "AlwaysIncludedSubnets should match expected value")

			require.ElementsMatch(test.expectedConfig.Filter.NeverIncludedSubnetsJSON, cfg.Filter.NeverIncludedSubnetsJSON, "NeverIncludedSubnetsJSON should match expected value")
			require.ElementsMatch(test.expectedConfig.Filter.NeverIncludedSubnets, cfg.Filter.NeverIncludedSubnets, "NeverIncludedSubnets should match expected value")

			require.ElementsMatch(test.expectedConfig.Filter.AlwaysIncludedDomains, cfg.Filter.AlwaysIncludedDomains, "AlwaysIncludedDomains should match expected value")
			require.ElementsMatch(test.expectedConfig.Filter.NeverIncludedDomains, cfg.Filter.NeverIncludedDomains, "NeverIncludedDomains should match expected value")

			require.Equal(test.expectedConfig.Filter.FilterExternalToInternal, cfg.Filter.FilterExternalToInternal, "FilterExternalToInternal should match expected value")

			require.Equal(test.expectedConfig.HTTPExtensionsFilePath, cfg.HTTPExtensionsFilePath, "HTTPExtensionsFilePath should match expected value")

			require.Equal(test.expectedConfig.BatchSize, cfg.BatchSize, "BatchSize should match expected value")
			require.Equal(test.expectedConfig.MaxQueryExecutionTime, cfg.MaxQueryExecutionTime, "MaxQuertExecutionTime should match expected value")

			require.Equal(test.expectedConfig.MonthsToKeepHistoricalFirstSeen, cfg.MonthsToKeepHistoricalFirstSeen, "MonthsToKeepHistoricalFirstSeen should match expected value")

			require.Equal(test.expectedConfig.ThreatIntel.OnlineFeeds, cfg.ThreatIntel.OnlineFeeds, "OnlineFeeds should match expected value")
			require.Equal(test.expectedConfig.ThreatIntel.CustomFeedsDirectory, cfg.ThreatIntel.CustomFeedsDirectory, "CustomFeedsDirectory should match expected value")

			require.Equal(test.expectedConfig.Scoring.Beacon.UniqueConnectionThreshold, cfg.Scoring.Beacon.UniqueConnectionThreshold, "BeaconUniqueConnectionThreshold should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.TsWeight, cfg.Scoring.Beacon.TsWeight, 0.00001, "BeaconTsWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.DsWeight, cfg.Scoring.Beacon.DsWeight, 0.00001, "BeaconDsWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.DurWeight, cfg.Scoring.Beacon.DurWeight, 0.00001, "BeaconDurWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.HistWeight, cfg.Scoring.Beacon.HistWeight, 0.00001, "BeaconHistWeight should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.DurMinHours, cfg.Scoring.Beacon.DurMinHours, "BeaconDurMinHoursSeen should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.DurIdealNumberOfConsistentHours, cfg.Scoring.Beacon.DurIdealNumberOfConsistentHours, "BeaconDurConsistencyIdealHoursSeen should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.HistModeSensitivity, cfg.Scoring.Beacon.HistModeSensitivity, 0.00001, "BeaconHistModeSensitivity should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.HistBimodalOutlierRemoval, cfg.Scoring.Beacon.HistBimodalOutlierRemoval, "BeaconHistBimodalOutlierRemoval should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.HistBimodalMinHours, cfg.Scoring.Beacon.HistBimodalMinHours, "BeaconHistBimodalMinHoursSeen should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Base, cfg.Scoring.Beacon.ScoreThresholds.Base, "BeaconScoreThresholds.Base should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Low, cfg.Scoring.Beacon.ScoreThresholds.Low, "BeaconScoreThresholds.Low should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Med, cfg.Scoring.Beacon.ScoreThresholds.Med, "BeaconScoreThresholds.Med should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.High, cfg.Scoring.Beacon.ScoreThresholds.High, "BeaconScoreThresholds.High should match expected value")

			require.Equal(test.expectedConfig.Scoring.LongConnectionMinimumDuration, cfg.Scoring.LongConnectionMinimumDuration, "LongConnectionMinimumDuration should match expected value")
			require.Equal(test.expectedConfig.Scoring.LongConnectionScoreThresholds.Base, cfg.Scoring.LongConnectionScoreThresholds.Base, "LongConnectionScoreThresholds.Base should match expected value")
			require.Equal(test.expectedConfig.Scoring.LongConnectionScoreThresholds.Low, cfg.Scoring.LongConnectionScoreThresholds.Low, "LongConnectionScoreThresholds.Low should match expected value")
			require.Equal(test.expectedConfig.Scoring.LongConnectionScoreThresholds.Med, cfg.Scoring.LongConnectionScoreThresholds.Med, "LongConnectionScoreThresholds.Med should match expected value")
			require.Equal(test.expectedConfig.Scoring.LongConnectionScoreThresholds.High, cfg.Scoring.LongConnectionScoreThresholds.High, "LongConnectionScoreThresholds.High should match expected value")

			require.Equal(test.expectedConfig.Scoring.C2SubdomainThreshold, cfg.Scoring.C2SubdomainThreshold, "C2SubdomainThreshold should match expected value")
			require.Equal(test.expectedConfig.Scoring.C2ScoreThresholds.Base, cfg.Scoring.C2ScoreThresholds.Base, "C2ScoreThresholds.Base should match expected value")
			require.Equal(test.expectedConfig.Scoring.C2ScoreThresholds.Low, cfg.Scoring.C2ScoreThresholds.Low, "C2ScoreThresholds.Low should match expected value")
			require.Equal(test.expectedConfig.Scoring.C2ScoreThresholds.Med, cfg.Scoring.C2ScoreThresholds.Med, "C2ScoreThresholds.Med should match expected value")
			require.Equal(test.expectedConfig.Scoring.C2ScoreThresholds.High, cfg.Scoring.C2ScoreThresholds.High, "C2ScoreThresholds.High should match expected value")

			require.Equal(test.expectedConfig.Scoring.StrobeImpact.Category, cfg.Scoring.StrobeImpact.Category, "StrobeImpact.Category should match expected value")
			require.InDelta(test.expectedConfig.Scoring.StrobeImpact.Score, cfg.Scoring.StrobeImpact.Score, 0.00001, "StrobeImpact.Score should match expected value")

			require.Equal(test.expectedConfig.Scoring.ThreatIntelImpact.Category, cfg.Scoring.ThreatIntelImpact.Category, "ThreatIntelImpact.Category should match expected value")
			require.InDelta(test.expectedConfig.Scoring.ThreatIntelImpact.Score, cfg.Scoring.ThreatIntelImpact.Score, 0.00001, "ThreatIntelImpact.Score to be %v, got %v", test.expectedConfig.Scoring.ThreatIntelImpact.Score, cfg.Scoring.ThreatIntelImpact.Score)

			require.InDelta(test.expectedConfig.Modifiers.ThreatIntelScoreIncrease, cfg.Modifiers.ThreatIntelScoreIncrease, 0.00001, "ThreatIntelScoreIncrease should match expected value")
			require.Equal(test.expectedConfig.Modifiers.ThreatIntelDataSizeThreshold, cfg.Modifiers.ThreatIntelDataSizeThreshold, "ThreatIntelDataSizeThreshold should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.PrevalenceScoreIncrease, cfg.Modifiers.PrevalenceScoreIncrease, 0.00001, "PrevalenceScoreIncrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.PrevalenceIncreaseThreshold, cfg.Modifiers.PrevalenceIncreaseThreshold, 0.00001, "PrevalenceIncreaseThreshold should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.PrevalenceScoreDecrease, cfg.Modifiers.PrevalenceScoreDecrease, 0.00001, "PrevalenceScoreDecrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.PrevalenceDecreaseThreshold, cfg.Modifiers.PrevalenceDecreaseThreshold, 0.00001, "PrevalenceDecreaseThreshold should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.FirstSeenScoreIncrease, cfg.Modifiers.FirstSeenScoreIncrease, 0.00001, "FirstSeenScoreIncrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.FirstSeenIncreaseThreshold, cfg.Modifiers.FirstSeenIncreaseThreshold, 0.00001, "FirstSeenIncreaseThreshold should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.FirstSeenScoreDecrease, cfg.Modifiers.FirstSeenScoreDecrease, 0.00001, "FirstSeenScoreDecrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.FirstSeenDecreaseThreshold, cfg.Modifiers.FirstSeenDecreaseThreshold, 0.00001, "FirstSeenDecreaseThreshold should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.MissingHostCountScoreIncrease, cfg.Modifiers.MissingHostCountScoreIncrease, 0.00001, "MissingHostCountScoreIncrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.RareSignatureScoreIncrease, cfg.Modifiers.RareSignatureScoreIncrease, 0.00001, "RareSignatureScoreIncrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.C2OverDNSDirectConnScoreIncrease, cfg.Modifiers.C2OverDNSDirectConnScoreIncrease, 0.00001, "C2OverDNSDirectConnScoreIncrease should match expected value")
			require.InDelta(test.expectedConfig.Modifiers.MIMETypeMismatchScoreIncrease, cfg.Modifiers.MIMETypeMismatchScoreIncrease, 0.00001, "MIMETypeMismatchScoreIncrease should match expected value")

			require.Equal(test.expectedConfig.LogLevel, cfg.LogLevel, "LogLevel should match expected value")
			require.Equal(test.expectedConfig.LoggingEnabled, cfg.LoggingEnabled, "LoggingEnabled should match expected value")
		})
	}
}

func TestReadFileConfig(t *testing.T) {

	tests := []struct {
		name           string
		configJSON     string
		expectedConfig Config
		expectedError  bool
	}{
		{
			name: "valid config",
			// create a JSON string to write to the temporary file
			configJSON: `{
					"db_connection": "localhost:9999",
					"filtering": {
						"internal_subnets": ["11.0.0.0/8", "120.130.140.150/8"],
						"always_included_subnets": [],
						"never_included_subnets": ["::1/128", "12.0.0.0/8", "150.140.150.160/8"],
						"always_included_domains": [],
						"never_included_domains": [],
						"filter_external_to_internal": true,
					},
					scoring: {
						beacon: {
							"unique_connection_threshold": 10,
							"timestamp_score_weight": 0.35,
							"datasize_score_weight": 0.20,
							"duration_score_weight": 0.35,
							"histogram_score_weight": 0.10,
							"score_thresholds": {
								"base": 0,
								"low": 1,
								"medium": 2,
								"high": 3
							}
						}
					}	
				}`,
			expectedConfig: Config{
				Filter: Filter{
					InternalSubnetsJSON: []string{"11.0.0.0/8", "120.130.140.150/8"},
					InternalSubnets: []*net.IPNet{
						{IP: net.IP{11, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{120, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
					},
					AlwaysIncludedSubnetsJSON: []string{},
					AlwaysIncludedSubnets:     nil,
					// mandatoryNeverIncludeSubnets are always apended to any neverIncludedSubnet entries
					// in this case we are including one of the mandatoryNeverIncludeSubnets in the neverIncludedSubnets list
					// to test that the mandatory entries are not duplicated when they are appended
					NeverIncludedSubnetsJSON: util.EnsureSliceContainsAll([]string{"::1/128", "12.0.0.0/8", "150.140.150.160/8"}, getMandatoryNeverIncludeSubnets()),
					NeverIncludedSubnets: []*net.IPNet{
						{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}, // would normally be appended with mandatory values at the end of config entries
						{IP: net.IP{12, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{150, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{0, 0, 0, 0}, Mask: net.IPMask{255, 255, 255, 255}},
						{IP: net.IP{127, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}},
						{IP: net.IP{169, 254, 0, 0}, Mask: net.IPMask{255, 255, 0, 0}},
						{IP: net.IP{224, 0, 0, 0}, Mask: net.IPMask{240, 0, 0, 0}},
						{IP: net.IP{255, 255, 255, 255}, Mask: net.IPMask{255, 255, 255, 255}},
						{IP: net.IPv6unspecified, Mask: net.CIDRMask(128, 128)},
						{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},
						{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)},
						{IP: net.ParseIP("ff02::2"), Mask: net.CIDRMask(128, 128)},
					},

					AlwaysIncludedDomains:    []string{},
					NeverIncludedDomains:     []string{},
					FilterExternalToInternal: true,
				},
				Scoring: Scoring{
					Beacon: Beacon{
						UniqueConnectionThreshold: 10,
						TsWeight:                  0.35,
						DsWeight:                  0.20,
						DurWeight:                 0.35,
						HistWeight:                0.10,
						ScoreThresholds: ScoreThresholds{
							Base: 0,
							Low:  1,
							Med:  2,
							High: 3,
						},
					},
				},
			},
			expectedError: false,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// create mock file system in memory
			afs := afero.NewMemMapFs()

			// get config file path
			configPath := fmt.Sprintf("test-config-%d.hjson", i)

			// create a temporary file to read from
			file, err := afs.Create(configPath)
			require.NoError(err, "creating file should not produce an error")

			// set file permissions
			err = afs.Chmod(configPath, os.FileMode(0o775))
			require.NoError(err, "changing file permissions should not produce an error")

			// write the JSON to temporary file
			bytesWritten, err := file.Write([]byte(test.configJSON))
			require.NoError(err, "writing data to file should not produce an error")
			require.Equal(len(test.configJSON), bytesWritten, "number of bytes written should be equal to the length of the mock data")

			// close temporary file
			err = file.Close()
			require.NoError(err, "closing file should not produce an error")

			// call function
			cfg, err := ReadFileConfig(afs, configPath)
			require.NoError(err, "Expected no error when reading file config, got err=%v", err)

			// verify that env variables are not overwritten by JSON
			// load environment variables with panic prevention
			err = godotenv.Overload("../.env", "../integration/test.env")
			require.NoError(err, "loading environment variables should not produce an error")
			// get the database connection string
			connection := os.Getenv("DB_ADDRESS")
			fmt.Println("connection: ", connection)
			require.Equal(connection, cfg.DBConnection, "DBConnection should not be overwritten by JSON and should match the env variable")

			// verify parsed values
			require.Equal(test.expectedConfig.Filter.InternalSubnetsJSON, cfg.Filter.InternalSubnetsJSON, "Expected InternalSubnetsJSON to be %v, got %v", test.expectedConfig.Filter.InternalSubnetsJSON, cfg.Filter.InternalSubnetsJSON)
			require.Equal(test.expectedConfig.Filter.InternalSubnets, cfg.Filter.InternalSubnets, "Expected InternalSubnets to be %v, got %v", test.expectedConfig.Filter.InternalSubnets, cfg.Filter.InternalSubnets)

			require.Equal(test.expectedConfig.Filter.AlwaysIncludedSubnetsJSON, cfg.Filter.AlwaysIncludedSubnetsJSON, "Expected AlwaysIncludedSubnetsJSON to be %v, got %v", test.expectedConfig.Filter.AlwaysIncludedSubnetsJSON, cfg.Filter.AlwaysIncludedSubnetsJSON)
			require.Equal(test.expectedConfig.Filter.AlwaysIncludedSubnets, cfg.Filter.AlwaysIncludedSubnets, "Expected AlwaysIncludedSubnets to be %v, got %v", test.expectedConfig.Filter.AlwaysIncludedSubnets, cfg.Filter.AlwaysIncludedSubnets)

			require.Equal(test.expectedConfig.Filter.NeverIncludedSubnetsJSON, cfg.Filter.NeverIncludedSubnetsJSON, "Expected NeverIncludedSubnetsJSON to be %v, got %v", test.expectedConfig.Filter.NeverIncludedSubnetsJSON, cfg.Filter.NeverIncludedSubnetsJSON)
			require.ElementsMatch(test.expectedConfig.Filter.NeverIncludedSubnets, cfg.Filter.NeverIncludedSubnets, "Expected NeverIncludedSubnets to be %v, got %v", test.expectedConfig.Filter.NeverIncludedSubnets, cfg.Filter.NeverIncludedSubnets)

			require.Equal(test.expectedConfig.Filter.AlwaysIncludedDomains, cfg.Filter.AlwaysIncludedDomains, "Expected AlwaysIncludedDomains to be %v, got %v", test.expectedConfig.Filter.AlwaysIncludedDomains, cfg.Filter.AlwaysIncludedDomains)
			require.Equal(test.expectedConfig.Filter.NeverIncludedDomains, cfg.Filter.NeverIncludedDomains, "Expected NeverIncludedDomains to be %v, got %v", test.expectedConfig.Filter.NeverIncludedDomains, cfg.Filter.NeverIncludedDomains)

			require.Equal(test.expectedConfig.Filter.FilterExternalToInternal, cfg.Filter.FilterExternalToInternal, "Expected FilterExternalToInternal to be %v, got %v", test.expectedConfig.Filter.FilterExternalToInternal, cfg.Filter.FilterExternalToInternal)

			require.Equal(test.expectedConfig.Scoring.Beacon.UniqueConnectionThreshold, cfg.Scoring.Beacon.UniqueConnectionThreshold, "Expected BeaconUniqueConnectionThreshold to be %v, got %v", test.expectedConfig.Scoring.Beacon.UniqueConnectionThreshold, cfg.Scoring.Beacon.UniqueConnectionThreshold)
			require.InDelta(test.expectedConfig.Scoring.Beacon.TsWeight, cfg.Scoring.Beacon.TsWeight, 0.00001, "BeaconTsWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.DsWeight, cfg.Scoring.Beacon.DsWeight, 0.00001, "BeaconDsWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.DurWeight, cfg.Scoring.Beacon.DurWeight, 0.00001, "BeaconDurWeight should match expected value")
			require.InDelta(test.expectedConfig.Scoring.Beacon.HistWeight, cfg.Scoring.Beacon.HistWeight, 0.00001, "BeaconHistWeight should match expected value")
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Base, cfg.Scoring.Beacon.ScoreThresholds.Base, "Expected BeaconScoreThresholds.Base to be %v, got %v", test.expectedConfig.Scoring.Beacon.ScoreThresholds.Base, cfg.Scoring.Beacon.ScoreThresholds.Base)
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Low, cfg.Scoring.Beacon.ScoreThresholds.Low, "Expected BeaconScoreThresholds.Low to be %v, got %v", test.expectedConfig.Scoring.Beacon.ScoreThresholds.Low, cfg.Scoring.Beacon.ScoreThresholds.Low)
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.Med, cfg.Scoring.Beacon.ScoreThresholds.Med, "Expected BeaconScoreThresholds.Med to be %v, got %v", test.expectedConfig.Scoring.Beacon.ScoreThresholds.Med, cfg.Scoring.Beacon.ScoreThresholds.Med)
			require.Equal(test.expectedConfig.Scoring.Beacon.ScoreThresholds.High, cfg.Scoring.Beacon.ScoreThresholds.High, "Expected BeaconScoreThresholds.High to be %v, got %v", test.expectedConfig.Scoring.Beacon.ScoreThresholds.High, cfg.Scoring.Beacon.ScoreThresholds.High)

			// clean up after the test
			err = afs.Remove(configPath)
			require.NoError(err, "removing temporary file should not produce an error")
		})
	}

}

func TestVerifyBeaconConfig(t *testing.T) {
	require := require.New(t)
	// get default config
	cfg, err := getDefaultConfig()
	require.NoError(err, "getDefaultConfig should not produce an error")

	// verify the default config
	err = cfg.verifyConfig()
	require.NoError(err, "verifyConfig should not produce an error")
	require.Equal(int64(4), cfg.Scoring.Beacon.UniqueConnectionThreshold, "BeaconUniqueConnectionThreshold should match expected value")
	require.InDelta(0.25, cfg.Scoring.Beacon.TsWeight, 0.00001, "BeaconTsWeight should match expected value")
	require.InDelta(0.25, cfg.Scoring.Beacon.DsWeight, 0.00001, "BeaconDsWeight should match expected value")
	require.InDelta(0.25, cfg.Scoring.Beacon.DurWeight, 0.00001, "BeaconDurWeight should match expected value")
	require.InDelta(0.25, cfg.Scoring.Beacon.HistWeight, 0.00001, "BeaconHistWeight should match expected value")
	require.Equal(6, cfg.Scoring.Beacon.DurMinHours, "BeaconDurMinHoursSeen should match expected value")
	require.Equal(12, cfg.Scoring.Beacon.DurIdealNumberOfConsistentHours, "BeaconDurIdealNumberOfConsistentHoursSeen should match expected value")
	require.InDelta(0.05, cfg.Scoring.Beacon.HistModeSensitivity, 0.00001, "BeaconHistModeSensitivity should match expected value")
	require.Equal(1, cfg.Scoring.Beacon.HistBimodalOutlierRemoval, "BeaconHistBimodalOutlierRemoval should match expected value")
	require.Equal(11, cfg.Scoring.Beacon.HistBimodalMinHours, "BeaconHistBimodalMinHoursSeen should match expected value")
}

func TestResetConfig(t *testing.T) {
	require := require.New(t)

	// get default config
	origConfig, err := getDefaultConfig()
	require.NoError(err, "Expected no error when getting default config, got err=%v", err)

	// create a copy of the config
	// cfg, err := getDefaultConfig()
	// require.NoError(err, "Expected no error when getting default config, got err=%v", err)
	cfg := origConfig

	// set some invalid values
	cfg.Scoring.Beacon.UniqueConnectionThreshold = 1
	cfg.Scoring.Beacon.TsWeight = 0.5
	cfg.Scoring.Beacon.DsWeight = 0.5
	cfg.Scoring.Beacon.DurWeight = 0.5
	cfg.Scoring.Beacon.HistWeight = 0.5
	cfg.Scoring.Beacon.DurMinHours = 0
	cfg.Scoring.Beacon.DurIdealNumberOfConsistentHours = 0
	cfg.Scoring.Beacon.HistModeSensitivity = 0
	cfg.Scoring.Beacon.HistBimodalOutlierRemoval = 0
	cfg.Scoring.Beacon.HistBimodalMinHours = 0
	cfg.Scoring.Beacon.ScoreThresholds = ScoreThresholds{
		Base: -1,
		Low:  -2,
		Med:  -3,
		High: -4,
	}

	// verify that the values are not the same before resetting
	require.NotEqual(origConfig, cfg, "config should not match default config")

	// reset the config
	err = cfg.ResetConfig()
	require.NoError(err, "resetting config should not produce an error")

	// verify that the values have been reset
	require.Equal(origConfig, cfg, "config should match expected value")

	// verify the config
	err = cfg.verifyConfig()
	require.NoError(err, "verifyConfig should not produce an error")
}

func TestGetDefaultConfig(t *testing.T) {
	require := require.New(t)
	cfg, err := getDefaultConfig()
	require.NoError(err, "getDefaultConfig should not produce an error")

	// get default config variable
	origConfigVar := defaultConfig()

	// get the database connection string
	connection := os.Getenv("DB_ADDRESS")
	require.NotEmpty(connection, "DB_ADDRESS should not be empty")
	origConfigVar.DBConnection = connection

	// parse the filter variables from the default config variable by hand to ensure they are correctly

	// parse internal subnets
	internalSubnetList, err := util.ParseSubnets(origConfigVar.Filter.InternalSubnetsJSON)
	require.NoError(err, "parseSubnets should not produce an error")
	origConfigVar.Filter.InternalSubnets = internalSubnetList

	// parse never included subnets
	origConfigVar.Filter.NeverIncludedSubnetsJSON = getMandatoryNeverIncludeSubnets()
	neverIncludedSubnetList, err := util.ParseSubnets(origConfigVar.Filter.NeverIncludedSubnetsJSON)
	require.NoError(err, "parseSubnets should not produce an error")
	origConfigVar.Filter.NeverIncludedSubnets = neverIncludedSubnetList

	// parse always included subnets
	alwayIncludedSubnetList, err := util.ParseSubnets(origConfigVar.Filter.AlwaysIncludedSubnetsJSON)
	require.NoError(err, "parseSubnets should not produce an error")
	origConfigVar.Filter.AlwaysIncludedSubnets = alwayIncludedSubnetList

	// verify that the object returned by the getDefaultConfig function is correct
	require.Equal(origConfigVar.DBConnection, cfg.DBConnection, "config db connection should match expected value")
	require.Equal(origConfigVar.UpdateCheckEnabled, cfg.UpdateCheckEnabled, "config update check enabled should match expected value")
	require.Equal(origConfigVar.Filter, cfg.Filter, "config internal subnets should match expected value")
	require.Equal(origConfigVar.HTTPExtensionsFilePath, cfg.HTTPExtensionsFilePath, "config http extensions file path should match expected value")
	require.Equal(origConfigVar.BatchSize, cfg.BatchSize, "config batch size should match expected value")
	require.Equal(origConfigVar.MonthsToKeepHistoricalFirstSeen, cfg.MonthsToKeepHistoricalFirstSeen, "config months to keep historical first seen should match expected value")
	require.Equal(origConfigVar.Scoring, cfg.Scoring, "config scoring should match expected value")
	require.Equal(origConfigVar.Modifiers, cfg.Modifiers, "config modifiers should match expected value")
	require.Equal(origConfigVar.ThreatIntel, cfg.ThreatIntel, "config threat intel should match expected value")
	require.Equal(origConfigVar.LogLevel, cfg.LogLevel, "config log level should match expected value")
	require.Equal(origConfigVar.LoggingEnabled, cfg.LoggingEnabled, "config logging enabled should match expected value")

	// match the whole object just in case
	require.Equal(origConfigVar, cfg, "config should match expected value")
}

func TestValidateScoreThresholds(t *testing.T) {
	tests := []struct {
		name          string
		thresholds    ScoreThresholds
		min           int
		max           int
		expectedError bool
	}{
		{
			name: "valid thresholds, (0 - 10)",
			thresholds: ScoreThresholds{
				Base: 0,
				Low:  1,
				Med:  2,
				High: 3,
			},
			min:           0,
			max:           10,
			expectedError: false,
		},
		{
			name: "valid beacon thresholds, (0 - 100)",
			thresholds: ScoreThresholds{
				Base: 50,
				Low:  75,
				Med:  90,
				High: 100,
			},
			min:           0,
			max:           100,
			expectedError: false,
		},
		{
			name: "valid long conn thresholds, (0 - 24*3600)",
			thresholds: ScoreThresholds{
				Base: 3600,
				Low:  4 * 3600,
				Med:  8 * 3600,
				High: 12 * 3600,
			},
			min:           0,
			max:           24 * 3600,
			expectedError: false,
		},
		{
			name: "valid c2 thresholds, (0 - no max)",
			thresholds: ScoreThresholds{
				Base: 100,
				Low:  500,
				Med:  800,
				High: 1000,
			},
			min:           0,
			max:           -1,
			expectedError: false,
		},
		{
			name: "invalid thresholds (not in ascending order)",
			thresholds: ScoreThresholds{
				Base: 0,
				Low:  1,
				Med:  2,
				High: 1,
			},
			min:           0,
			max:           10,
			expectedError: true,
		},
		{
			name: "invalid thresholds (out of range - max)",
			thresholds: ScoreThresholds{
				Base: 0,
				Low:  1,
				Med:  2,
				High: 3,
			},
			min:           0,
			max:           2,
			expectedError: true,
		},
		{
			name: "invalid thresholds (out of range - min)",
			thresholds: ScoreThresholds{
				Base: 0,
				Low:  1,
				Med:  2,
				High: 3,
			},
			min:           1,
			max:           10,
			expectedError: true,
		},
		{
			name: "invalid thresholds (two thresholds equal)",
			thresholds: ScoreThresholds{
				Base: 0,
				Low:  1,
				Med:  1,
				High: 3,
			},
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

func TestParseImpactCategoryScores(t *testing.T) {
	t.Run("Valid Categories", func(t *testing.T) {
		cfg := &Config{
			Scoring: Scoring{
				StrobeImpact: ScoreImpact{
					Category: HighThreat,
				},
				ThreatIntelImpact: ScoreImpact{
					Category: LowThreat,
				},
			},
		}

		err := cfg.parseImpactCategoryScores()
		require.NoError(t, err)
		require.InDelta(t, float32(HIGH_CATEGORY_SCORE), cfg.Scoring.StrobeImpact.Score, 0.0001, "StrobeImpact.Score should match expected value")
		require.InDelta(t, float32(LOW_CATEGORY_SCORE), cfg.Scoring.ThreatIntelImpact.Score, 0.0001, "ThreatIntelImpact.Score should match expected value")
	})

	t.Run("More Valid Categories", func(t *testing.T) {
		cfg := &Config{
			Scoring: Scoring{
				StrobeImpact: ScoreImpact{
					Category: MediumThreat,
				},
				ThreatIntelImpact: ScoreImpact{
					Category: NoneThreat,
				},
			},
		}

		err := cfg.parseImpactCategoryScores()
		require.NoError(t, err)
		require.InDelta(t, float32(MEDIUM_CATEGORY_SCORE), cfg.Scoring.StrobeImpact.Score, 0.0001, "StrobeImpact.Score should match expected value")
		require.InDelta(t, float32(NONE_CATEGORY_SCORE), cfg.Scoring.ThreatIntelImpact.Score, 0.0001, "ThreatIntelImpact.Score should match expected value")
	})

	t.Run("Invalid Category for StrobeImpact", func(t *testing.T) {
		cfg := &Config{
			Scoring: Scoring{
				StrobeImpact: ScoreImpact{
					Category: "unknown",
				},
				ThreatIntelImpact: ScoreImpact{
					Category: LowThreat,
				},
			},
		}

		err := cfg.parseImpactCategoryScores()
		require.Error(t, err)
	})

	t.Run("Invalid Category for ThreatIntelImpact", func(t *testing.T) {
		cfg := &Config{
			Scoring: Scoring{
				StrobeImpact: ScoreImpact{
					Category: HighThreat,
				},
				ThreatIntelImpact: ScoreImpact{
					Category: "invalid",
				},
			},
		}

		err := cfg.parseImpactCategoryScores()
		require.Error(t, err)
	})
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
