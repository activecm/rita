package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"
	"github.com/go-playground/validator/v10"

	"github.com/hjson/hjson-go/v4"
	"github.com/spf13/afero"
)

var Version string

const DefaultConfigPath = "./config.hjson"

var errInvalidImpactCategory = errors.New("invalid impact category: must be 'high', 'medium', 'low', or 'none'")
var errReadingConfigFile = errors.New("encountered an error while reading the config file")

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
		Env          Env `json:"env" validate:"required"`
		RITA         `validate:"required"`
		Filtering    Filtering    `json:"filtering" validate:"required"`
		Scoring      Scoring      `json:"scoring" validate:"required"`
		Modifiers    Modifiers    `json:"modifiers" validate:"required"`
		ZoneTransfer ZoneTransfer `json:"zone_transfer"`
	}

	Env struct { // set by .env file
		DBConnection                    string `validate:"required,hostname_port"` // DB_ADDRESS
		DBUsername                      string `json:"-"`
		DBPassword                      string `json:"-"`
		HTTPExtensionsFilePath          string `validate:"file"`        // CONFIG_DIR/http_extensions_list.csv
		LogLevel                        int8   `validate:"min=0,max=6"` // LOG_LEVEL
		ThreatIntelCustomFeedsDirectory string `validate:"dir"`         // CONFIG_DIR/threat_intel_feeds
	}

	RITA struct {
		UpdateCheckEnabled              bool  `ch:"update_check_enabled" json:"update_check_enabled" validate:"boolean"`
		BatchSize                       int32 `ch:"batch_size" json:"batch_size" validate:"gte=25000,lte=2000000"`
		MaxQueryExecutionTime           int32 `ch:"max_query_execution_time" json:"max_query_execution_time" validate:"gte=1,lte=2000000"`
		MonthsToKeepHistoricalFirstSeen int32 `ch:"months_to_keep_historical_first_seen" json:"months_to_keep_historical_first_seen" validate:"gte=1,lte=60"`
		ThreatIntel                     `json:"threat_intel"`
	}

	ThreatIntel struct {
		OnlineFeeds []string `ch:"threat_intel_online_feeds" json:"online_feeds" validate:"omitempty,dive,url"`
	}

	Filtering struct {
		// subnets do not need a validate tag because they are validated when they are unmarshalled
		InternalSubnets          []util.Subnet `ch:"internal_subnets" json:"internal_subnets" validate:"required,gt=0"`
		AlwaysIncludedSubnets    []util.Subnet `ch:"always_included_subnets" json:"always_included_subnets"`
		AlwaysIncludedDomains    []string      `ch:"always_included_domains" json:"always_included_domains" validate:"omitempty,dive,wildcard_fqdn"`
		NeverIncludedSubnets     []util.Subnet `ch:"never_included_subnets" json:"never_included_subnets" validate:"required,gt=0"`
		NeverIncludedDomains     []string      `ch:"never_included_domains" json:"never_included_domains" validate:"omitempty,dive,wildcard_fqdn"`
		FilterExternalToInternal bool          `ch:"filter_external_to_internal" json:"filter_external_to_internal" validate:"boolean"`
	}

	Scoring struct {
		Beacon        BeaconScoring `json:"beacon" validate:"required"`
		ThreatScoring `validate:"required"`
	}

	ZoneTransfer struct {
		Enabled    bool   `ch:"enabled" json:"enabled"`
		DomainName string `ch:"domain_name" json:"domain_name" validate:"required_if=Enabled true,omitempty,fqdn"`
		NameServer string `ch:"name_server" json:"name_server" validate:"required_if=Enabled true,omitempty,hostname_port"`
	}

	BeaconScoring struct {
		UniqueConnectionThreshold         int64           `ch:"unique_connection_threshold" json:"unique_connection_threshold" validate:"gte=4"`
		TimestampScoreWeight              float64         `ch:"timestamp_score_weight" json:"timestamp_score_weight" validate:"gte=0,lte=1"`
		DatasizeScoreWeight               float64         `ch:"datasize_score_weight" json:"datasize_score_weight" validate:"gte=0,lte=1"`
		DurationScoreWeight               float64         `ch:"duration_score_weight" json:"duration_score_weight" validate:"gte=0,lte=1"`
		HistogramScoreWeight              float64         `ch:"histogram_score_weight" json:"histogram_score_weight" validate:"gte=0,lte=1"`
		DurationMinHoursSeen              int32           `ch:"duration_min_hours_seen" json:"duration_min_hours_seen" validate:"gte=1,lte=24"`
		DurationConsistencyIdealHoursSeen int32           `ch:"duration_consistency_ideal_hours_seen" json:"duration_consistency_ideal_hours_seen" validate:"gte=1,lte=24"`
		HistogramModeSensitivity          float64         `ch:"histogram_mode_sensitivity" json:"histogram_mode_sensitivity" validate:"gte=0,lte=1"`
		HistogramBimodalOutlierRemoval    int32           `ch:"histogram_bimodal_outlier_removal" json:"histogram_bimodal_outlier_removal" validate:"gte=0,lte=24"`
		HistogramBimodalMinHoursSeen      int32           `ch:"histogram_bimodal_min_hours_seen" json:"histogram_bimodal_min_hours_seen" validate:"gte=3,lte=24"`
		ScoreThresholds                   ScoreThresholds `ch:"score_thresholds" json:"score_thresholds" validate:"score_thresholds_range=0 100"`
	}

	ThreatScoring struct {
		LongConnectionScoreThresholds ScoreThresholds `json:"long_connection_score_thresholds" validate:"score_thresholds_range=1 86400"` // 24 * 3600
		C2ScoreThresholds             ScoreThresholds `json:"c2_score_thresholds" validate:"score_thresholds_range=1 -1"`
		StrobeImpact                  ScoreImpact     `ch:"strobe_impact_category" json:"strobe_impact" validate:"impact_category"`
		ThreatIntelImpact             ScoreImpact     `ch:"threat_intel_impact_category" json:"threat_intel_impact" validate:"impact_category"`
	}

	Modifiers struct {
		ThreatIntelScoreIncrease         float64 `ch:"threat_intel_score_increase" json:"threat_intel_score_increase" validate:"gte=0,lte=1"`
		ThreatIntelDataSizeThreshold     int64   `ch:"threat_intel_datasize_threshold" json:"threat_intel_datasize_threshold"  validate:"gte=1,lte=5000000000"`
		PrevalenceScoreIncrease          float64 `ch:"prevalence_score_increase" json:"prevalence_score_increase" validate:"gte=0,lte=1"`
		PrevalenceIncreaseThreshold      float64 `ch:"prevalence_increase_threshold" json:"prevalence_increase_threshold" validate:"gte=0,lte=1"`
		PrevalenceScoreDecrease          float64 `ch:"prevalence_score_decrease" json:"prevalence_score_decrease" validate:"gte=0,lte=1"`
		PrevalenceDecreaseThreshold      float64 `ch:"prevalence_decrease_threshold" json:"prevalence_decrease_threshold" validate:"gte=0,lte=1,gtfield=PrevalenceIncreaseThreshold"`
		FirstSeenScoreIncrease           float64 `ch:"first_seen_score_increase" json:"first_seen_score_increase" validate:"gte=0,lte=1"`
		FirstSeenIncreaseThreshold       float64 `ch:"first_seen_increase_threshold" json:"first_seen_increase_threshold" validate:"gte=1,lte=90"`
		FirstSeenScoreDecrease           float64 `ch:"first_seen_score_decrease" json:"first_seen_score_decrease" validate:"gte=0,lte=1"`
		FirstSeenDecreaseThreshold       float64 `ch:"first_seen_decrease_threshold" json:"first_seen_decrease_threshold" validate:"gte=1,lte=90,gtfield=FirstSeenIncreaseThreshold"`
		MissingHostCountScoreIncrease    float64 `ch:"missing_host_count_score_increase" json:"missing_host_count_score_increase" validate:"gte=0,lte=1"`
		RareSignatureScoreIncrease       float64 `ch:"rare_signature_score_increase" json:"rare_signature_score_increase" validate:"gte=0,lte=1"`
		C2OverDNSDirectConnScoreIncrease float64 `ch:"c2_over_dns_direct_conn_score_increase" json:"c2_over_dns_direct_conn_score_increase" validate:"gte=0,lte=1"`
		MIMETypeMismatchScoreIncrease    float64 `ch:"mime_type_mismatch_score_increase" json:"mime_type_mismatch_score_increase" validate:"gte=0,lte=1"`
	}

	// ScoreThresholds is used for indicators that have prorated (graduated) values rather than
	// binary outcomes. This allows for the definition of the severity of an indicator by categorizing
	// it into one of several buckets (Base, Low, Med, High), each representing a range of values. These
	// values must be in increasing order and unique.
	ScoreThresholds struct {
		Base int32 `json:"base" ch:"base" validate:"ltfield=Low"`
		Low  int32 `json:"low" ch:"low" validate:"ltfield=Med"`
		Med  int32 `json:"medium" ch:"med" validate:"ltfield=High"`
		High int32 `json:"high" ch:"high"`
	}

	// ScoreImpact is used for indicators that have a binary outcomes but still need to express the
	// impact of being true on the overall score.
	ScoreImpact struct {
		Category ImpactCategory `json:"category"`
		Score    float64
	}

	ImpactCategory string
)

// ReadFileConfig attempts to read the config file at the specified path and
// returns a config object, using the default config if the file was unable to be read.
func ReadFileConfig(afs afero.Fs, path string) (*Config, error) {
	// read the config file
	contents, err := util.GetFileContents(afs, path)
	if err != nil {
		return nil, err
	}
	// fmt.Println("contents:", contents)
	var cfg Config
	// // parse the JSON config file
	// if err := hjson.Unmarshal(contents, &cfg); err != nil {
	// 	return nil, err
	// }
	if err := unmarshal(contents, &cfg, nil); err != nil {
		return nil, fmt.Errorf("%w, located by default at '%s', please correct the issue in the config and try again:\n\t- %w", errReadingConfigFile, path, err)
	}
	// // set the environment variables
	// if err := setEnv(&cfg); err != nil {
	// 	return nil, fmt.Errorf("unable to set environment: %w", err)
	// }

	return &cfg, nil
}

// ReadConfigFromMemory reads the config from bytes already read into memory as opposed to reading from a file
// It also provides its own environment struct that must already be completely set
func ReadConfigFromMemory(data []byte, env Env) (*Config, error) {
	var cfg Config
	if err := unmarshal(data, &cfg, &env); err != nil {
		return nil, err
	}
	return &cfg, nil

}

func (c *Config) setEnv() error {
	// get the database connection string
	connection := os.Getenv("DB_ADDRESS")
	if connection == "" {
		return errors.New("environment variable DB_ADDRESS not set")
	}
	c.Env.DBConnection = connection

	dbUsername := os.Getenv("CLICKHOUSE_USERNAME")
	if dbUsername == "" {
		return errors.New("environment variable CLICKHOUSE_USERNAME not set")
	}
	c.Env.DBUsername = dbUsername
	dbPassword := os.Getenv("CLICKHOUSE_PASSWORD")
	// don't check if CLICKHOUSE_PASSWORD is set because it can be empty
	c.Env.DBPassword = dbPassword

	// get the log level
	logLevelStr := os.Getenv("LOG_LEVEL")
	if logLevelStr == "" {
		return errors.New("environment variable LOG_LEVEL not set")
	}
	logLevel, err := strconv.Atoi(logLevelStr)
	if err != nil {
		return fmt.Errorf("unable to convert LOG_LEVEL to int: %w", err)
	}
	c.Env.LogLevel = int8(logLevel)

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		return errors.New("environment variable CONFIG_DIR not set")
	}
	configDirFull, err := filepath.Abs(configDir)
	if err != nil {
		return fmt.Errorf("unable to get absolute path to CONFIG_DIR environment variable: %s, err: %w", configDir, err)
	}
	c.Env.HTTPExtensionsFilePath = filepath.Join(configDirFull, "http_extensions_list.csv")
	c.Env.ThreatIntelCustomFeedsDirectory = filepath.Join(configDirFull, "threat_intel_feeds")
	return nil
}

// unmarshal unmarshals the data into the config struct, sets the environment variables, and validates the values
func unmarshal(data []byte, cfg *Config, env *Env) error {
	// unmarshal the JSON config file
	if err := hjson.Unmarshal(data, &cfg); err != nil {
		// fmt.Println("UNMARSHAL HAS ERROR :(", string(data))
		return err
	}

	// set the environment struct
	// this MUST be done before validating the values, because the
	// validation checks for the presence of the environment variables
	if env == nil {
		// set the environment variables from the actual environment
		if err := cfg.setEnv(); err != nil {
			return fmt.Errorf("unable to set environment: %w", err)
		}
	} else {
		// set the environment variables from the provided environment struct
		cfg.Env = *env
	}

	// validate values
	if err := cfg.Validate(); err != nil {
		return err
	}
	return nil
}

// // UnmarshalJSON unmarshals the JSON bytes into the config struct
// // overrides the default unmarshalling method to allow for custom parsing
func (c *Config) UnmarshalJSON(bytes []byte) error {
	// create temporary config struct to unmarshal into
	// not doing this would result in an infinite unmarshalling loop
	type tmpConfig Config
	defaultCfg := GetDefaultConfig()

	// set the default config to a variable of the temporary type
	tmpCfg := tmpConfig(defaultCfg)

	// unmarshal json into the default config struct
	err := hjson.Unmarshal(bytes, &tmpCfg)
	if err != nil {
		return err
	}

	// convert the temporary config struct to a config struct
	cfg := Config(tmpCfg)
	// validate internal subnets
	cfg.Filtering.InternalSubnets = util.CompactSubnets(cfg.Filtering.InternalSubnets)

	// validate never included subnets
	cfg.Filtering.NeverIncludedSubnets = util.IncludeMandatorySubnets(cfg.Filtering.NeverIncludedSubnets, GetMandatoryNeverIncludeSubnets())
	cfg.Filtering.NeverIncludedSubnets = util.CompactSubnets(cfg.Filtering.NeverIncludedSubnets)

	// clean up always included subnets
	cfg.Filtering.AlwaysIncludedSubnets = util.CompactSubnets(cfg.Filtering.AlwaysIncludedSubnets)

	// parse impact category scores
	if err := cfg.parseImpactCategoryScores(); err != nil {
		return err
	}

	// set the new config values
	*c = cfg

	return nil
}

// GetDefaultConfig returns a Config object with default values
func GetDefaultConfig() Config {
	// set version to dev if not set
	if Version == "" {
		Version = "dev"
	}

	// set default config values
	cfg := defaultConfig()

	return cfg
}

// Reset resets the config values to default
// note: Env values are not reset
func (cfg *Config) Reset() error {
	// store the environment values before resetting
	env := cfg.Env

	// get the default config
	newConfig := GetDefaultConfig()

	*cfg = newConfig
	cfg.Env = env

	// validate the config struct
	if err := cfg.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate validates the config struct values
func (cfg *Config) Validate() error {
	zlog := logger.GetLogger()
	zlog.Debug().Interface("config", cfg).Msg("validating config")

	// create a new validator
	validate, err := NewValidator()
	if err != nil {
		return err
	}

	// validate the config struct
	if err := validate.Struct(cfg); err != nil {
		return err
	}

	return nil
}

// NewValidator creates a new validator with custom validation rules
func NewValidator() (*validator.Validate, error) {
	v := validator.New(validator.WithRequiredStructEnabled())

	// register custom validation for impact category
	if err := v.RegisterValidation("impact_category", func(fl validator.FieldLevel) bool {
		value := fl.Field().Interface().(ScoreImpact)
		err := ValidateImpactCategory(value.Category)
		return err == nil
	}); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("score_thresholds_range", func(fl validator.FieldLevel) bool {
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
		err := validateScoreThresholdsRange(value, int32(min), int32(max))
		return err == nil
	}); err != nil {
		return nil, err
	}

	v.RegisterStructValidation(func(sl validator.StructLevel) {
		value := sl.Current().Interface().(BeaconScoring)
		totalWeight := value.TimestampScoreWeight + value.DatasizeScoreWeight + value.DurationScoreWeight + value.HistogramScoreWeight
		if totalWeight != 1 {
			sl.ReportError(value, "TimestampScoreWeight", "BeaconScoring", "beacon_weights", "")
			sl.ReportError(value, "DatasizeScoreWeight", "BeaconScoring", "beacon_weights", "")
			sl.ReportError(value, "DurationScoreWeight", "BeaconScoring", "beacon_weights", "")
			sl.ReportError(value, "HistogramScoreWeight", "BeaconScoring", "beacon_weights", "")
		}
	}, BeaconScoring{})

	// validate fqdns and fqdns with wildcards
	if err := v.RegisterValidation("wildcard_fqdn", func(fl validator.FieldLevel) bool {
		value := fl.Field().Interface().(string)
		// If it starts with "*.", strip it out
		value = strings.TrimPrefix(value, "*.")
		return v.Var(value, "fqdn") == nil
	}); err != nil {
		return nil, err
	}

	return v, nil
}

// validateScoreThresholdsRange validates that the score thresholds are in range based on the provided min and max values.
// A value of -1 for either min or max indicates the lack of that boundary.
func validateScoreThresholdsRange(s ScoreThresholds, min int32, max int32) error {
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

func GetScoreFromImpactCategory(category ImpactCategory) (float64, error) {
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

func GetImpactCategoryFromScore(score float64) ImpactCategory {
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
	case score > 0 && score <= NONE_CATEGORY_SCORE:
		return NoneThreat
	}

	return NoneThreat
}

func (s *ScoreThresholds) ToMap() map[string]int32 {
	return map[string]int32{
		"base": s.Base,
		"low":  s.Low,
		"med":  s.Med,
		"high": s.High,
	}

}

func (s ScoreImpact) String() string {
	return string(s.Category)
}

func (s *ScoreImpact) Scan(src any) error {
	if t, ok := src.(string); ok {
		s.Category = ImpactCategory(t)
		score, err := GetScoreFromImpactCategory(s.Category)
		if err != nil {
			return err
		}
		s.Score = score
		return nil
	}
	return fmt.Errorf("cannot scan %T into ScoreImpact", src)
}

// return a copy of the default config object
func defaultConfig() Config {
	return Config{
		RITA: RITA{
			UpdateCheckEnabled:              true,
			BatchSize:                       100000,
			MaxQueryExecutionTime:           240,
			MonthsToKeepHistoricalFirstSeen: 3,
			ThreatIntel: ThreatIntel{
				OnlineFeeds: []string{
					"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
				},
			},
		},
		Filtering: Filtering{
			InternalSubnets: []util.Subnet{
				{IPNet: &net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},    // "10.0.0.0/8"
				{IPNet: &net.IPNet{IP: net.IP{172, 16, 0, 0}.To16(), Mask: net.CIDRMask(108, 128)}},  // "172.16.0.0/12"
				{IPNet: &net.IPNet{IP: net.IP{192, 168, 0, 0}.To16(), Mask: net.CIDRMask(112, 128)}}, // "192.168.0.0/16"
				{IPNet: &net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(8, 128)}},           // "fd00::/8"
			},
			AlwaysIncludedSubnets:    []util.Subnet{},
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
		ZoneTransfer: ZoneTransfer{
			Enabled:    false,
			DomainName: "",
			NameServer: "",
		},
	}
}

// ONLY TO BE CALLED IN TESTS
// helper function to set the env variables that are reliant on paths since tests use the path of the package
func (c *Config) SetTestEnv() {
	fmt.Println(c)
	c.setEnv()
	c.Env.HTTPExtensionsFilePath = "../deployment/http_extensions_list.csv"
	c.Env.ThreatIntelCustomFeedsDirectory = "../deployment/threat_intel_feeds"
}

// ReadTestFileConfig is for TESTS only
func ReadTestFileConfig(afs afero.Fs, path string) (*Config, error) {
	// read the config file
	contents, err := util.GetFileContents(afs, path)
	if err != nil {
		return nil, err
	}

	// create a temporary config just to generate the environment
	var tmpCfg Config
	if err := tmpCfg.setEnv(); err != nil {
		return nil, fmt.Errorf("unable to set environment variables for TEST environment")
	}
	// override path based variables since tests use their package directory
	tmpCfg.Env.HTTPExtensionsFilePath = "../deployment/http_extensions_list.csv"
	tmpCfg.Env.ThreatIntelCustomFeedsDirectory = "../deployment/threat_intel_feeds"

	var cfg Config
	if err := unmarshal(contents, &cfg, &tmpCfg.Env); err != nil {
		return nil, fmt.Errorf("%w, located by default at '%s', please correct the issue in the config and try again:\n\t- %w", errReadingConfigFile, path, err)
	}

	return &cfg, nil
}
