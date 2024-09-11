package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/activecm/rita/v5/util"
	"github.com/go-playground/validator/v10"

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
	Config struct {
		Env Env
		RITA
		Filtering Filtering `json:"filtering"`
		Scoring   Scoring
		Modifiers Modifiers
	}

	Env struct { // set by .env file
		DBConnection           string `validate:"required,hostname_port"`
		HTTPExtensionsFilePath string `json:"http_extensions_file_path" validate:"required,file"`
	}

	RITA struct {
		UpdateCheckEnabled              bool  `ch:"update_check_enabled" json:"update_check_enabled" validate:"boolean"` // required,
		BatchSize                       int32 `ch:"batch_size" json:"batch_size" validate:"gte=25000,lte=2000000"`
		MaxQueryExecutionTime           int32 `ch:"max_query_execution_time" json:"max_query_execution_time" validate:"gte=1,lte=2000000"`
		MonthsToKeepHistoricalFirstSeen int32 `ch:"months_to_keep_historical_first_seen" json:"months_to_keep_historical_first_seen" validate:"gte=1,lte=60"`
		LogLevel                        int8  `ch:"log_level"` // TODO: question - should this be in the env struct?

		// TODO: probably put these back into a separate struct for better unmarshal
		ThreatIntel `json:"threat_intel"`
		// ThreatIntelOnlineFeeds          []string `ch:"threat_intel_online_feeds" json:"threat_intel_online_feeds"`
		// ThreatIntelCustomFeedsDirectory string   `ch:"threat_intel_custom_feeds_directory" json:"threat_intel_custom_feeds_directory" validate:"required"`
	}

	ThreatIntel struct {
		OnlineFeeds []string `ch:"threat_intel_online_feeds" json:"online_feeds" validate:"omitempty,dive,url"`
		// TODO: should we do the dir validation? it verifies the directory exists, but do we want to do that now or later like we have been?
		// It would probably be nice to do it here rather than after all the filewalk stuff, but it will fail on non-docker runs unless we create the directory by hand
		// another option would be to just write a custom validator function that checks if the string has a slash or something..
		CustomFeedsDirectory string `ch:"threat_intel_custom_feeds_directory" json:"custom_feeds_directory" validate:"required"`
	}

	Filtering struct {
		// cannot use cidr validate tag because it doesn't support ipv4 mapped ipv6 addresses
		// see: https://github.com/go-playground/validator/issues/1311
		//required,
		InternalSubnets          []util.IPNet `ch:"internal_subnets" json:"internal_subnets" validate:"internal_subnets"`
		AlwaysIncludedSubnets    []util.IPNet `ch:"always_included_subnets" json:"always_included_subnets"`
		AlwaysIncludedDomains    []string     `ch:"always_included_domains" json:"always_included_domains" validate:"omitempty,dive,fqdn"`
		NeverIncludedSubnets     []util.IPNet `ch:"never_included_subnets" json:"never_included_subnets"`
		NeverIncludedDomains     []string     `ch:"never_included_domains" json:"never_included_domains" validate:"omitempty,dive,fqdn"`
		FilterExternalToInternal bool         `ch:"filter_external_to_internal" json:"filter_external_to_internal" validate:"boolean"`
	}

	Scoring struct {
		Beacon        BeaconScoring `json:"beacon" validate:"beacon_scoring"`
		ThreatScoring               // see if this works
	}

	// TODO: is the required tag just for fields that must be filled out in the hjson file or is it fields that must be set, be it by default function or by user?
	BeaconScoring struct {
		UniqueConnectionThreshold         int64           `ch:"unique_connection_threshold" json:"unique_connection_threshold" validate:"gte=4"`
		TimestampScoreWeight              float64         `ch:"timestamp_score_weight" json:"timestamp_score_weight" validate:"gte=0,lte=1"`
		DatasizeScoreWeight               float64         `ch:"datasize_score_weight" json:"datasize_score_weight" validate:"gte=0,lte=1"`
		DurationScoreWeight               float64         `ch:"duration_score_weight" json:"duration_score_weight" validate:"gte=0,lte=1"`
		HistogramScoreWeight              float64         `ch:"histogram_score_weight" json:"histogram_score_weight" validate:"gte=0,lte=1"`
		DurationMinHoursSeen              int32           `ch:"duration_min_hours_seen" json:"duration_min_hours_seen" validate:"gte=1"`
		DurationConsistencyIdealHoursSeen int32           `ch:"duration_consistency_ideal_hours_seen" json:"duration_consistency_ideal_hours_seen" validate:"gte=1"`
		HistogramModeSensitivity          float64         `ch:"histogram_mode_sensitivity" json:"histogram_mode_sensitivity" validate:"gte=0,lte=1"`
		HistogramBimodalOutlierRemoval    int32           `ch:"histogram_bimodal_outlier_removal" json:"histogram_bimodal_outlier_removal" validate:"gte=0"`
		HistogramBimodalMinHoursSeen      int32           `ch:"histogram_bimodal_min_hours_seen" json:"histogram_bimodal_min_hours_seen" validate:"gte=3,lte=24"`
		ScoreThresholds                   ScoreThresholds `ch:"score_thresholds" json:"score_thresholds" validate:"score_thresholds=0 100"`
	}

	ThreatScoring struct {
		LongConnectionScoreThresholds ScoreThresholds `json:"long_connection_score_thresholds" validate:"score_thresholds=1 86400"` // 24 * 3600

		C2ScoreThresholds ScoreThresholds `json:"c2_score_thresholds" validate:"score_thresholds=1 -1"`

		StrobeImpact ScoreImpact `json:"strobe_impact" validate:"impact_category"`

		ThreatIntelImpact ScoreImpact `json:"threat_intel_impact" validate:"impact_category"`
	}

	// Scoring struct {
	// 	LongConnectionBaseScoreThresh   int32  `ch:"long_connection_base_score_thresh" json:"long_connection_base_score_thresh" validate:"gt=0,ltfield=LongConnectionLowScoreThresh"`
	// 	LongConnectionLowScoreThresh    int32  `ch:"long_connection_low_score_thresh" json:"long_connection_low_score_thresh" validate:"gt=0,ltfield=LongConnectionMediumScoreThresh"`
	// 	LongConnectionMediumScoreThresh int32  `ch:"long_connection_medium_score_thresh" json:"long_connection_medium_score_thresh" validate:"gt=0,ltfield=LongConnectionHighScoreThresh"`
	// 	LongConnectionHighScoreThresh   int32  `ch:"long_connection_high_score_thresh" json:"long_connection_high_score_thresh" validate:"gt=0,lte=86400"`
	// 	C2BaseScoreThresh               int32  `ch:"c2_base_score_thresh" json:"c2_base_score_thresh" validate:"gt=0,ltfield=C2LowScoreThresh"`
	// 	C2LowScoreThresh                int32  `ch:"c2_low_score_thresh" json:"c2_low_score_thresh" validate:"gt=0,ltfield=C2MediumScoreThresh"`
	// 	C2MediumScoreThresh             int32  `ch:"c2_medium_score_thresh" json:"c2_medium_score_thresh" validate:"gt=0,ltfield=C2HighScoreThresh"`
	// 	C2HighScoreThresh               int32  `ch:"c2_high_score_thresh" json:"c2_high_score_thresh" validate:"gt=0"`
	// 	StrobeImpactCategory            string `ch:"strobe_impact_category" json:"strobe_impact_category" validate:"impact_category"`
	// 	ThreatIntelImpactCategory       string `ch:"threat_intel_impact_category" json:"threat_intel_impact_category" validate:"impact_category"`
	// }

	Modifiers struct {
		ThreatIntelScoreIncrease         float32 `ch:"threat_intel_score_increase" json:"threat_intel_score_increase" validate:"gte=0,lte=1"`
		ThreatIntelDataSizeThreshold     int64   `ch:"threat_intel_datasize_threshold" json:"threat_intel_datasize_threshold"  validate:"gte=1"`
		PrevalenceScoreIncrease          float32 `ch:"prevalence_score_increase" json:"prevalence_score_increase" validate:"gte=0,lte=1"`
		PrevalenceIncreaseThreshold      float32 `ch:"prevalence_increase_threshold" json:"prevalence_increase_threshold" validate:"gte=0,lte=1"`
		PrevalenceScoreDecrease          float32 `ch:"prevalence_score_decrease" json:"prevalence_score_decrease" validate:"gte=0,lte=1"`
		PrevalenceDecreaseThreshold      float32 `ch:"prevalence_decrease_threshold" json:"prevalence_decrease_threshold" validate:"gte=0,lte=1,gtfield=PrevalenceIncreaseThreshold"`
		FirstSeenScoreIncrease           float32 `ch:"first_seen_score_increase" json:"first_seen_score_increase" validate:"gte=0,lte=1"`
		FirstSeenIncreaseThreshold       float32 `ch:"first_seen_increase_threshold" json:"first_seen_increase_threshold" validate:"gte=1"`
		FirstSeenScoreDecrease           float32 `ch:"first_seen_score_decrease" json:"first_seen_score_decrease" validate:"gte=0,lte=1"`
		FirstSeenDecreaseThreshold       float32 `ch:"first_seen_decrease_threshold" json:"first_seen_decrease_threshold" validate:"gte=1,lte=90,gtfield=FirstSeenIncreaseThreshold"`
		MissingHostCountScoreIncrease    float32 `ch:"missing_host_count_score_increase" json:"missing_host_count_score_increase" validate:"gte=0,lte=1"`
		RareSignatureScoreIncrease       float32 `ch:"rare_signature_score_increase" json:"rare_signature_score_increase" validate:"gte=0,lte=1"`
		C2OverDNSDirectConnScoreIncrease float32 `ch:"c2_over_dns_direct_conn_score_increase" json:"c2_over_dns_direct_conn_score_increase" validate:"gte=0,lte=1"`
		MIMETypeMismatchScoreIncrease    float32 `ch:"mime_type_mismatch_score_increase" json:"mime_type_mismatch_score_increase" validate:"gte=0,lte=1"`
	}

	// ScoreThresholds is used for indicators that have prorated (graduated) values rather than
	// binary outcomes. This allows for the definition of the severity of an indicator by categorizing
	// it into one of several buckets (Base, Low, Med, High), each representing a range of values
	ScoreThresholds struct {
		Base int32 `json:"base"`
		Low  int32 `json:"low"`
		Med  int32 `json:"medium"`
		High int32 `json:"high"`
	}

	// ScoreImpact is used for indicators that have a binary outcomes but still need to express the
	// impact of being true on the overall score.
	ScoreImpact struct {
		Category ImpactCategory `json:"category"`
		Score    float32
	}

	ImpactCategory string
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

	// // parse the new subnet filter values
	// if err := cfg.parseFilter(); err != nil {
	// 	return err
	// }

	cfg.Filtering.NeverIncludedSubnets = append(cfg.Filtering.NeverIncludedSubnets, GetMandatoryNeverIncludeSubnets()...)

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
	cfg.Env.DBConnection = connection

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		return Config{}, errors.New("environment variable CONFIG_DIR not set")
	}
	configDirFull, err := filepath.Abs(configDir)
	if err != nil {
		return Config{}, fmt.Errorf("unable to get absolute path to CONFIG_DIR environment variable: %s, err: %w", configDir, err)
	}
	cfg.Env.HTTPExtensionsFilePath = filepath.Join(configDirFull, "http_extensions_list.csv")

	// set up the filter based on default values
	// (must be done to convert strings in the default config variable to net.IPNet)
	// err = cfg.parseFilter()
	// if err != nil {
	// 	return cfg, err
	// }

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

// Reset resets the config values to default
func (cfg *Config) Reset() error {
	newConfig, err := GetDefaultConfig()
	if err != nil {
		return err
	}
	*cfg = newConfig
	return nil
}

// Validate validates the config struct values
func (cfg *Config) Validate() error {
	validate, err := newValidator()
	if err != nil {
		return err
	}

	// validate the config struct
	if err := validate.Struct(cfg); err != nil {
		return err
	}
	return nil
}

func newValidator() (*validator.Validate, error) {
	v := validator.New(validator.WithRequiredStructEnabled())

	// register custom validation for impact category
	if err := v.RegisterValidation("impact_category", func(fl validator.FieldLevel) bool {
		value := fl.Field().Interface().(ScoreImpact)
		// cat := ImpactCategory(value)
		err := ValidateImpactCategory(value.Category)
		return err == nil
	}); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("score_thresholds", func(fl validator.FieldLevel) bool {
		value := fl.Field().Interface().(ScoreThresholds)
		// get the param string and parse it into two integers (min and max)
		params := strings.Split(fl.Param(), " ")
		if len(params) != 2 {
			return false
		}
		min, err1 := strconv.ParseInt(params[0], 10, 32)
		max, err2 := strconv.ParseInt(params[1], 10, 32)
		if err1 != nil || err2 != nil {
			return false
		}
		err := validateScoreThresholds(value, int32(min), int32(max))
		return err == nil
	}); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("internal_subnets", func(fl validator.FieldLevel) bool {
		return len(fl.Field().Interface().([]util.IPNet)) >= 1
		// TODO: validate internal subnet cidrs
	}); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("beacon_scoring", func(fl validator.FieldLevel) bool {
		value := fl.Field().Interface().(BeaconScoring)
		// verify that sum of weights is 1
		totalWeight := value.TimestampScoreWeight + value.DatasizeScoreWeight + value.DurationScoreWeight + value.HistogramScoreWeight
		return totalWeight == 1
	}); err != nil {
		return nil, err
	}

	return v, nil
}

// validateScoreThresholds validates the score thresholds based on the provided min and max values
func validateScoreThresholds(s ScoreThresholds, min int32, max int32) error {
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
		RITA: RITA{
			UpdateCheckEnabled:              true,
			BatchSize:                       100000,
			MaxQueryExecutionTime:           120,
			MonthsToKeepHistoricalFirstSeen: 3,
			ThreatIntel: ThreatIntel{
				OnlineFeeds:          []string{},
				CustomFeedsDirectory: "/etc/rita/threat_intel_feeds",
			},
		},
		Filtering: Filtering{
			InternalSubnets: []util.IPNet{
				{IPNet: &net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},    // "10.0.0.0/8"
				{IPNet: &net.IPNet{IP: net.IP{172, 16, 0, 0}.To16(), Mask: net.CIDRMask(108, 128)}},  // "172.16.0.0/12"
				{IPNet: &net.IPNet{IP: net.IP{192, 168, 0, 0}.To16(), Mask: net.CIDRMask(112, 128)}}, // "192.168.0.0/16"
				{IPNet: &net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(8, 128)}},           // "fd00::/8"
			},
			AlwaysIncludedSubnets:    []util.IPNet{},
			NeverIncludedSubnets:     GetMandatoryNeverIncludeSubnets(),
			AlwaysIncludedDomains:    []string{},
			NeverIncludedDomains:     []string{},
			FilterExternalToInternal: true,
		},
		Scoring: Scoring{
			Beacon: BeaconScoring{
				UniqueConnectionThreshold:         4,
				TimestampScoreWeight:              0.25,
				DatasizeScoreWeight:               0.25,
				DurationScoreWeight:               0.25,
				HistogramScoreWeight:              0.25,
				DurationMinHoursSeen:              6,
				DurationConsistencyIdealHoursSeen: 12,
				HistogramModeSensitivity:          0.05,
				HistogramBimodalOutlierRemoval:    1,
				HistogramBimodalMinHoursSeen:      11,
				ScoreThresholds: ScoreThresholds{
					Base: 50,
					Low:  75,
					Med:  90,
					High: 100,
				},
			},
			ThreatScoring: ThreatScoring{
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
	}
}
