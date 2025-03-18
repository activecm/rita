package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/activecm/rita/v5/util"

	"github.com/hjson/hjson-go/v4"
	"github.com/spf13/afero"
)

var Version string

const DefaultConfigPath = "./config.hjson"

var errInvalidImpactCategory = errors.New("invalid impact category: must be 'critical', 'high', 'medium', 'low', or 'none'")

const (
	NONE_CATEGORY_SCORE   = 0.2
	LOW_CATEGORY_SCORE    = 0.4
	MEDIUM_CATEGORY_SCORE = 0.6
	HIGH_CATEGORY_SCORE   = 0.8

	CriticalThreat ImpactCategory = "critical"
	HighThreat     ImpactCategory = "high"
	MediumThreat   ImpactCategory = "medium"
	LowThreat      ImpactCategory = "low"
	NoneThreat     ImpactCategory = "none"
)

type (
	ThreatIntel struct {
		OnlineFeeds          []string `json:"online_feeds"`
		CustomFeedsDirectory string   `json:"custom_feeds_directory"`
	}

	// ScoreThresholds is used for indicators that have prorated (graduated) values rather than
	// binary outcomes. This allows for the definition of the severity of an indicator by categorizing
	// it into one of several buckets (Base, Low, Med, High), each representing a range of values
	ScoreThresholds struct {
		Base int `json:"base"`
		Low  int `json:"low"`
		Med  int `json:"medium"`
		High int `json:"high"`
	}

	ImpactCategory string

	// ScoreImpact is used for indicators that have a binary outcomes but still need to express the
	// impact of being true on the overall score.
	ScoreImpact struct {
		Category ImpactCategory `json:"category"`
		Score    float32
	}

	Scoring struct {
		Beacon Beacon `json:"beacon"`

		LongConnectionScoreThresholds ScoreThresholds `json:"long_connection_score_thresholds"`

		C2ScoreThresholds ScoreThresholds `json:"c2_score_thresholds"`

		StrobeImpact ScoreImpact `json:"strobe_impact"`

		ThreatIntelImpact ScoreImpact `json:"threat_intel_impact"`
	}

	Modifiers struct {
		ThreatIntelScoreIncrease     float32 `json:"threat_intel_score_increase"`
		ThreatIntelDataSizeThreshold int64   `json:"threat_intel_datasize_threshold"`

		PrevalenceScoreIncrease     float32 `json:"prevalence_score_increase"`
		PrevalenceIncreaseThreshold float32 `json:"prevalence_increase_threshold"`
		PrevalenceScoreDecrease     float32 `json:"prevalence_score_decrease"`
		PrevalenceDecreaseThreshold float32 `json:"prevalence_decrease_threshold"`

		FirstSeenScoreIncrease     float32 `json:"first_seen_score_increase"`
		FirstSeenIncreaseThreshold float32 `json:"first_seen_increase_threshold"`
		FirstSeenScoreDecrease     float32 `json:"first_seen_score_decrease"`
		FirstSeenDecreaseThreshold float32 `json:"first_seen_decrease_threshold"`

		MissingHostCountScoreIncrease float32 `json:"missing_host_count_score_increase"`

		RareSignatureScoreIncrease float32 `json:"rare_signature_score_increase"`

		C2OverDNSDirectConnScoreIncrease float32 `json:"c2_over_dns_direct_conn_score_increase"`

		MIMETypeMismatchScoreIncrease float32 `json:"mime_type_mismatch_score_increase"`
	}

	Beacon struct {
		UniqueConnectionThreshold       int64           `json:"unique_connection_threshold"`
		TsWeight                        float64         `json:"timestamp_score_weight"`
		DsWeight                        float64         `json:"datasize_score_weight"`
		DurWeight                       float64         `json:"duration_score_weight"`
		HistWeight                      float64         `json:"histogram_score_weight"`
		DurMinHours                     int             `json:"duration_min_hours_seen"`
		DurIdealNumberOfConsistentHours int             `json:"duration_consistency_ideal_hours_seen"`
		HistModeSensitivity             float64         `json:"histogram_mode_sensitivity"`
		HistBimodalOutlierRemoval       int             `json:"histogram_bimodal_outlier_removal"`
		HistBimodalMinHours             int             `json:"histogram_bimodal_min_hours_seen"`
		ScoreThresholds                 ScoreThresholds `json:"score_thresholds"`
	}

	Config struct {
		DBConnection       string // set by .env file
		UpdateCheckEnabled bool   `json:"update_check_enabled"`
		Filter             Filter `json:"filtering"`

		HTTPExtensionsFilePath string `json:"http_extensions_file_path"`

		// writer
		BatchSize             int `json:"batch_size"`
		MaxQueryExecutionTime int `json:"max_query_execution_time"`

		// historical first seen
		MonthsToKeepHistoricalFirstSeen int `json:"months_to_keep_historical_first_seen"`

		Scoring Scoring `json:"scoring"`

		Modifiers Modifiers `json:"modifiers"`

		ThreatIntel ThreatIntel `json:"threat_intel"`
	}
)

// ReadFileConfig attempts to read the config file at the specified path and
// returns a config object, using the default config if the file was unable to be read.
func ReadFileConfig(afs afero.Fs, path string) (*Config, error) {
	// read the config file
	contents, err := readFile(afs, path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	// parse the JSON config file
	if err := hjson.Unmarshal(contents, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// UnmarshalJSON unmarshals the JSON bytes into the config struct
// overrides the default unmarshalling method to allow for custom parsing
func (c *Config) UnmarshalJSON(bytes []byte) error {
	// create temporary config struct to unmarshal into
	// not doing this would result in an infinite unmarshalling loop

	type tmpConfig Config
	// init default config
	defaultCfg, err := GetDefaultConfig()
	if err != nil {
		return err
	}

	// set the default config to a variable of the temporary type
	tmpCfg := tmpConfig(defaultCfg)

	// unmarshal json into the default config struct
	err = hjson.Unmarshal(bytes, &tmpCfg)
	if err != nil {
		return err
	}

	// convert the temporary config struct to a config struct
	cfg := Config(tmpCfg)

	// parse the new subnet filter values
	if err := cfg.parseFilter(); err != nil {
		return err
	}

	// parse impact category scores
	if err := cfg.parseImpactCategoryScores(); err != nil {
		return err
	}

	// validate values
	err = cfg.Validate()
	if err != nil {
		return err
	}

	// set the new config values
	*c = cfg

	return nil
}

// GetDefaultConfig returns a Config object with default values
func GetDefaultConfig() (Config, error) {
	// set version to dev if not set
	if Version == "" {
		Version = "dev"
	}

	// set default config values
	cfg := defaultConfig()

	// get the database connection string
	connection := os.Getenv("DB_ADDRESS")
	if connection == "" {
		return Config{}, errors.New("environment variable DB_ADDRESS not set")
	}
	cfg.DBConnection = connection

	// set up the filter based on default values
	// (must be done to convert strings in the default config variable to net.IPNet)
	err := cfg.parseFilter()
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

// readFile reads the config file at the specified path and returns its contents
func readFile(afs afero.Fs, path string) ([]byte, error) {
	// validate file
	err := util.ValidateFile(afs, path)
	if err != nil {
		return nil, err
	}

	file, err := afero.ReadFile(afs, path)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// ResetConfig resets the config values to default
func (cfg *Config) ResetConfig() error {
	newConfig, err := GetDefaultConfig()
	if err != nil {
		return err
	}
	*cfg = newConfig
	return nil
}

func (cfg *Config) Validate() error {
	// validate the configured values
	if err := cfg.verifyConfig(); err != nil {
		return err
	}
	return nil
}

// verifyConfig validates the configuration settings
func (cfg *Config) verifyConfig() error {
	if cfg.DBConnection == "" {
		return fmt.Errorf("DBConnection cannot be empty")
	}

	// validate that there is at least one internal subnet, or else we cannot do analysis
	if len(cfg.Filter.InternalSubnets) < 1 {
		return fmt.Errorf("the list of internal subnets is empty, got %v", cfg.Filter.InternalSubnets)
	}

	if len(cfg.HTTPExtensionsFilePath) < 1 {
		return fmt.Errorf("the valid HTTP extensions file path is not set, got %v", cfg.HTTPExtensionsFilePath)
	}

	// validate the batch size
	if cfg.BatchSize < 25000 || cfg.BatchSize > 2000000 {
		return fmt.Errorf("the batch size for writing to the database must be between 25k and 2 million")
	}

	// validate the max query execution time
	if cfg.MaxQueryExecutionTime < 1 || cfg.MaxQueryExecutionTime > 2000000 {
		return fmt.Errorf("the max database query execution time must be between 1 second and 2 million seconds")
	}

	// validate historical first seen months
	if cfg.MonthsToKeepHistoricalFirstSeen < 1 || cfg.MonthsToKeepHistoricalFirstSeen > 60 {
		return fmt.Errorf("the historical first seen months must be between 1 and 60, got %v", cfg.MonthsToKeepHistoricalFirstSeen)
	}

	// validate the configured unique connection threshold (need at least 3 intervals, which means at least 4 connections)
	if cfg.Scoring.Beacon.UniqueConnectionThreshold < 4 {
		return fmt.Errorf("the unique connection threshold must be at least 4, got %v", cfg.Scoring.Beacon.UniqueConnectionThreshold)
	}

	// validate the configured score weights
	totalWeight := 0.0
	weights := []float64{
		cfg.Scoring.Beacon.TsWeight,
		cfg.Scoring.Beacon.DsWeight,
		cfg.Scoring.Beacon.DurWeight,
		cfg.Scoring.Beacon.HistWeight,
	}
	for _, weight := range weights {
		if weight < 0 || weight > 1 {
			return fmt.Errorf("the weight must be between 0 and 1, got %v", weight)
		}
		totalWeight += weight
	}

	// sum of weights must equal 1
	if totalWeight != 1 {
		return fmt.Errorf("the sum of the weights must equal 1, got %v", totalWeight)
	}

	// validate the configured minimum hours seen for duration
	if cfg.Scoring.Beacon.DurMinHours < 1 {
		return fmt.Errorf("the minimum hours seen for duration must be at least 1, got %v", cfg.Scoring.Beacon.DurMinHours)
	}

	// validate the configured ideal number of consistent hours seen
	if cfg.Scoring.Beacon.DurIdealNumberOfConsistentHours < 1 {
		return fmt.Errorf("the ideal number of consistent hours seen must be at least 1, got %v", cfg.Scoring.Beacon.DurIdealNumberOfConsistentHours)
	}

	// validate the configured mode sensitivity
	if cfg.Scoring.Beacon.HistModeSensitivity < 0 || cfg.Scoring.Beacon.HistModeSensitivity > 1 {
		return fmt.Errorf("the mode sensitivity must be between 0 and 1, got %v", cfg.Scoring.Beacon.HistModeSensitivity)
	}

	// validate the configured bimodal outlier removal
	if cfg.Scoring.Beacon.HistBimodalOutlierRemoval < 0 {
		return fmt.Errorf("the bimodal outlier removal must be at least 0, got %v", cfg.Scoring.Beacon.HistBimodalOutlierRemoval)
	}

	// validate the configured min hours seen for histogram
	// this is to ensure that the bimodal fit score is not calculated for histograms with too few hours, as in that case
	// a histogram with 1-2 bars will always be given a high bimoal fit score as it technically has 1-2 modes
	if cfg.Scoring.Beacon.HistBimodalMinHours < 3 {
		return fmt.Errorf("the minimum hours seen for histogram must be at least 3, got %v", cfg.Scoring.Beacon.HistBimodalMinHours)
	}

	// validate the configured beacon score thresholds ( scores are between 0 and 100 )
	if err := validateScoreThresholds(cfg.Scoring.Beacon.ScoreThresholds, 0, 100); err != nil {
		return err
	}

	// validate the configured long connection minimum duration
	if cfg.Scoring.LongConnectionScoreThresholds.Base <= 0 {
		return fmt.Errorf("the long connection minimum duration must be at least greater than 0, got %v", cfg.Scoring.LongConnectionScoreThresholds.Base)
	}

	// validate the configured long connection score thresholds ( between 0 and 24 hours )
	if err := validateScoreThresholds(cfg.Scoring.LongConnectionScoreThresholds, 0, 24*3600); err != nil {
		return err
	}

	// validate the configured C2 subdomain threshold
	if cfg.Scoring.C2ScoreThresholds.Base <= 0 {
		return fmt.Errorf("the C2 subdomain threshold must be at least greater than 0, got %v", cfg.Scoring.C2ScoreThresholds.Base)
	}

	// validate the configured C2 score thresholds ( no max limit )
	if err := validateScoreThresholds(cfg.Scoring.C2ScoreThresholds, 0, -1); err != nil {
		return err
	}

	// validate the configured strobe impact category
	if err := ValidateImpactCategory(cfg.Scoring.StrobeImpact.Category); err != nil {
		return err
	}

	// threat intel struct can be empty, so no need for validation

	// validate the configured threat intel impact category
	if err := ValidateImpactCategory(cfg.Scoring.ThreatIntelImpact.Category); err != nil {
		return err
	}

	// validate the configured threat intel modifier values
	if cfg.Modifiers.ThreatIntelScoreIncrease < 0 || cfg.Modifiers.ThreatIntelScoreIncrease > 1 {
		return fmt.Errorf("the threat intel modifier score increase must be between 0 and 1, got %v", cfg.Modifiers.ThreatIntelScoreIncrease)
	}
	// validate the configured threat intel modifier data size threshold (must be greater than 0 and less than the max int64 value)
	if cfg.Modifiers.ThreatIntelDataSizeThreshold < 1 {
		return fmt.Errorf("the threat intel modifier data size threshold must be greater than 0, got %v", cfg.Modifiers.ThreatIntelScoreIncrease)
	}

	// validate the configured prevalence score increase modifier values
	if cfg.Modifiers.PrevalenceScoreIncrease < 0 || cfg.Modifiers.PrevalenceScoreIncrease > 1 {
		return fmt.Errorf("the prevalence modifier score increase must be between 0 and 1, got %v", cfg.Modifiers.PrevalenceScoreIncrease)
	}
	// validate score increase threshold
	if cfg.Modifiers.PrevalenceIncreaseThreshold < 0 || cfg.Modifiers.PrevalenceIncreaseThreshold > 1 {
		return fmt.Errorf("the prevalence modifier increase threshold must be between 0 and 1, got %v", cfg.Modifiers.PrevalenceIncreaseThreshold)
	}

	// validate the configured prevalence score decrease modifier values
	if cfg.Modifiers.PrevalenceScoreDecrease < 0 || cfg.Modifiers.PrevalenceScoreDecrease > 1 {
		return fmt.Errorf("the prevalence modifier score decrease must be between 0 and 1, got %v", cfg.Modifiers.PrevalenceScoreDecrease)
	}
	// validate score decrease threshold (must be between 0 and 1 and greater than the increase threshold)
	if cfg.Modifiers.PrevalenceDecreaseThreshold < 0 || cfg.Modifiers.PrevalenceDecreaseThreshold > 1 {
		return fmt.Errorf("the prevalence modifier decrease threshold must be between 0 and 1, got %v", cfg.Modifiers.PrevalenceDecreaseThreshold)
	}
	if cfg.Modifiers.PrevalenceDecreaseThreshold <= cfg.Modifiers.PrevalenceIncreaseThreshold {
		return fmt.Errorf("the prevalence modifier decrease threshold must be greater than the increase threshold, got %v", cfg.Modifiers.PrevalenceDecreaseThreshold)
	}

	// validate the configured first seen score increase modifier values (must be between 0 and 1)
	if cfg.Modifiers.FirstSeenScoreIncrease < 0 || cfg.Modifiers.FirstSeenScoreIncrease > 1 {
		return fmt.Errorf("the first seen modifier score increase must be between 0 and 1, got %v", cfg.Modifiers.FirstSeenScoreIncrease)
	}
	// validate first seen score increase threshold (must be a positive number)
	if cfg.Modifiers.FirstSeenIncreaseThreshold < 0 {
		return fmt.Errorf("the first seen modifier increase threshold must be a positive number of days, got %v", cfg.Modifiers.FirstSeenIncreaseThreshold)
	}

	// validate the configured first seen score decrease modifier values (must be between 0 and 1)
	if cfg.Modifiers.FirstSeenScoreDecrease < 0 || cfg.Modifiers.FirstSeenScoreDecrease > 1 {
		return fmt.Errorf("the first seen modifier score decrease must be between 0 and 1, got %v", cfg.Modifiers.FirstSeenScoreDecrease)
	}

	// validate first seen score decrease threshold (positive number and greater than the increase threshold)
	if cfg.Modifiers.FirstSeenDecreaseThreshold < 0 {
		return fmt.Errorf("the first seen modifier decrease threshold must be between 0 and 90 days, got %v", cfg.Modifiers.FirstSeenDecreaseThreshold)
	}
	if cfg.Modifiers.FirstSeenDecreaseThreshold <= cfg.Modifiers.FirstSeenIncreaseThreshold {
		return fmt.Errorf("the first seen modifier decrease threshold must be greater than the increase threshold, got %v", cfg.Modifiers.FirstSeenDecreaseThreshold)
	}

	// validate the configured missing host count score increase (must be between 0 and 1)
	if cfg.Modifiers.MissingHostCountScoreIncrease < 0 || cfg.Modifiers.MissingHostCountScoreIncrease > 1 {
		return fmt.Errorf("the missing host count score increase must be between 0 and 1, got %v", cfg.Modifiers.MissingHostCountScoreIncrease)
	}

	// validate the configured rare signature score increase
	if cfg.Modifiers.RareSignatureScoreIncrease < 0 || cfg.Modifiers.RareSignatureScoreIncrease > 1 {
		return fmt.Errorf("the rare signature score increase must be between 0 and 1, got %v", cfg.Modifiers.RareSignatureScoreIncrease)
	}

	// validate the configured c2 over DNS direct connection score increase
	if cfg.Modifiers.C2OverDNSDirectConnScoreIncrease < 0 || cfg.Modifiers.C2OverDNSDirectConnScoreIncrease > 1 {
		return fmt.Errorf("the c2 over DNS direct connection score increase must be between 0 and 1, got %v", cfg.Modifiers.C2OverDNSDirectConnScoreIncrease)
	}

	// validate the configured MIME type/URI mismatch score increase
	if cfg.Modifiers.MIMETypeMismatchScoreIncrease < 0 || cfg.Modifiers.MIMETypeMismatchScoreIncrease > 1 {
		return fmt.Errorf("the MIME type/URI mismatch score increase must be between 0 and 1, got %v", cfg.Modifiers.MIMETypeMismatchScoreIncrease)
	}

	return nil
}

// validateScoreThresholds validates the score thresholds based on the provided min and max values
func validateScoreThresholds(s ScoreThresholds, min int, max int) error {
	// check if values are in increasing order and unique
	if s.Base >= s.Low || s.Low >= s.Med || s.Med >= s.High {
		return fmt.Errorf("score thresholds must be in increasing order and unique: %v", s)
	}

	// validate that base is in range (if min is provided)
	if min > -1 && s.Base < min {
		return fmt.Errorf("base score threshold must be greater than or equal to %d", min)
	}

	// validate that high is in range (if max is provided)
	if max > -1 && s.High > max {
		return fmt.Errorf("high score threshold must be less than or equal to %d", max)
	}

	return nil
}

// parseImpactCategoryScores sets the corresponding scores for the binary indicators
func (cfg *Config) parseImpactCategoryScores() error {

	strobeScore, err := GetScoreFromImpactCategory(cfg.Scoring.StrobeImpact.Category)
	if err != nil {
		return err
	}

	cfg.Scoring.StrobeImpact.Score = strobeScore

	threatIntelScore, err := GetScoreFromImpactCategory(cfg.Scoring.ThreatIntelImpact.Category)
	if err != nil {
		return err
	}

	cfg.Scoring.ThreatIntelImpact.Score = threatIntelScore

	return nil

}

// ValidateImpactCategory checks if the provided string is a valid impact value.
// this function is meant to parse the category from the value a user places in the config
// Since a score is only critical if its modifiers boost the score over the high category,
// we do not add the CriticalThreat category here
func ValidateImpactCategory(value ImpactCategory) error {
	switch value {
	case HighThreat, MediumThreat, LowThreat, NoneThreat:
		return nil
	default:
		return errInvalidImpactCategory
	}
}

func GetScoreFromImpactCategory(category ImpactCategory) (float32, error) {
	switch {
	case category == HighThreat:
		return HIGH_CATEGORY_SCORE, nil
	case category == MediumThreat:
		return MEDIUM_CATEGORY_SCORE, nil
	case category == LowThreat:
		return LOW_CATEGORY_SCORE, nil
	case category == NoneThreat:
		return NONE_CATEGORY_SCORE, nil
	}
	return 0, errInvalidImpactCategory
}

func GetImpactCategoryFromScore(score float32) ImpactCategory {
	switch {
	// >80%
	case score > MEDIUM_CATEGORY_SCORE:
		return HighThreat
		// >40% and <=60%
	case score > LOW_CATEGORY_SCORE && score <= MEDIUM_CATEGORY_SCORE:
		return MediumThreat
		// >20% and <=40%
	case score > NONE_CATEGORY_SCORE && score <= LOW_CATEGORY_SCORE:
		return LowThreat
		// <=20%
	case score <= NONE_CATEGORY_SCORE:
		return NoneThreat
	}

	return NoneThreat
}

// return a copy of the default config object
func defaultConfig() Config {
	return Config{
		UpdateCheckEnabled: true,
		Filter: Filter{
			InternalSubnetsJSON:       []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"},
			AlwaysIncludedSubnetsJSON: []string{},
			NeverIncludedSubnetsJSON:  GetMandatoryNeverIncludeSubnets(),
			AlwaysIncludedDomains:     []string{},
			NeverIncludedDomains:      []string{},
			FilterExternalToInternal:  true,
			FilterFailedConnections:   false,
		},
		HTTPExtensionsFilePath:          "./http_extensions_list.csv",
		BatchSize:                       100000,
		MaxQueryExecutionTime:           120,
		MonthsToKeepHistoricalFirstSeen: 3,
		Scoring: Scoring{
			Beacon: Beacon{
				UniqueConnectionThreshold:       4,
				TsWeight:                        0.25,
				DsWeight:                        0.25,
				DurWeight:                       0.25,
				HistWeight:                      0.25,
				DurMinHours:                     6,
				DurIdealNumberOfConsistentHours: 12,
				HistModeSensitivity:             0.05,
				HistBimodalOutlierRemoval:       1,
				HistBimodalMinHours:             11,
				ScoreThresholds: ScoreThresholds{
					Base: 50,
					Low:  75,
					Med:  90,
					High: 100,
				},
			},

			LongConnectionScoreThresholds: ScoreThresholds{
				Base: 1 * 3600, // 1 hour (in seconds),
				Low:  4 * 3600,
				Med:  8 * 3600,
				High: 12 * 3600,
			},

			C2ScoreThresholds: ScoreThresholds{
				Base: 100,
				Low:  500,
				Med:  800,
				High: 1000,
			},

			StrobeImpact: ScoreImpact{Category: HighThreat, Score: HIGH_CATEGORY_SCORE},

			ThreatIntelImpact: ScoreImpact{Category: HighThreat, Score: HIGH_CATEGORY_SCORE},
		},
		Modifiers: Modifiers{
			ThreatIntelScoreIncrease:     0.15,   // score +15% if data size >= 25 MB
			ThreatIntelDataSizeThreshold: 2.5e+7, // 25 MB (as bytes)

			PrevalenceScoreIncrease:     0.15, // score +15% if prevalence <= 2%
			PrevalenceIncreaseThreshold: 0.02,
			PrevalenceScoreDecrease:     0.15, // score -15% if prevalence >= 50%
			PrevalenceDecreaseThreshold: 0.5,  // must be greater than the increase threshold

			FirstSeenScoreIncrease:     0.15, // score +15% if first seen <= 7 days ago
			FirstSeenIncreaseThreshold: 7,
			FirstSeenScoreDecrease:     0.15, // score -15% if first seen >= 30 days ago
			FirstSeenDecreaseThreshold: 30,   // must be greater than the increase threshold
			// because the longer a host has been seen on the network, the less sus it is

			MissingHostCountScoreIncrease: 0.10, // +10% score for any (>0) missing hosts

			RareSignatureScoreIncrease: 0.15, // +15% score for connections with a rare signature

			C2OverDNSDirectConnScoreIncrease: 0.15, // +15% score for domains that were queried but had no direct connections

			MIMETypeMismatchScoreIncrease: 0.15, // +15% score for connections with mismatched MIME type/URI
		},
		ThreatIntel: ThreatIntel{
			OnlineFeeds:          []string{},
			CustomFeedsDirectory: "/etc/rita/threat_intel_feeds",
		},
	}
}
