package analysis

import (
	"context"
	"fmt"
	"math"
	"net"
	"runtime"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

type Analyzer struct {
	Database        *database.DB
	ImportID        util.FixedString
	Config          *config.Config
	AnalysisWorkers int
	WriterWorkers   int
	UconnChan       chan AnalysisResult
	maxTS           time.Time
	minTS           time.Time
	maxTSBeacon     time.Time
	minTSBeacon     time.Time
	networkSize     uint64
	useCurrentTime  bool
	skipBeaconing   bool
	firstSeenMaxTS  time.Time

	writer *database.BulkWriter
}

type ThreatMixtape struct {
	AnalyzedAt time.Time        `ch:"analyzed_at"`
	ImportID   util.FixedString `ch:"import_id"`

	// Base connection details
	AnalysisResult

	FinalScore float64 `ch:"final_score"`
	// BEACONS
	Beacon
	BeaconThreatScore float64 `ch:"beacon_threat_score"` // bucketed beacon score
	BeaconType        string  `ch:"beacon_type"`

	//  LONG CONNECTIONS
	LongConnScore float64 `ch:"long_conn_score"`

	// Strobe
	Strobe      bool    `ch:"strobe"`
	StrobeScore float64 `ch:"strobe_score"`

	// C2 over DNS
	C2OverDNSScore           float64 `ch:"c2_over_dns_score"`
	C2OverDNSDirectConnScore float64 `ch:"c2_over_dns_direct_conn_score"`

	// Threat Intel
	ThreatIntel      bool    `ch:"threat_intel"`
	ThreatIntelScore float64 `ch:"threat_intel_score"`

	// **** MODIFIERS ****
	// for modifiers detected during the modifiers phase
	ModifierName  string  `ch:"modifier_name"`
	ModifierScore float64 `ch:"modifier_score"`
	ModifierValue string  `ch:"modifier_value"`

	// modifiers that are able to be added to the same row as the threat indicator scores
	// these are detected during the analysis phase (in the spagooper)
	PrevalenceScore          float64 `ch:"prevalence_score"`
	NetworkSize              uint64  `ch:"network_size"`
	FirstSeenScore           float64 `ch:"first_seen_score"`
	ThreatIntelDataSizeScore float64 `ch:"threat_intel_data_size_score"`
	MissingHostHeaderScore   float64 `ch:"missing_host_header_score"`
}

// NewAnalyzer returns a new Analyzer object
func NewAnalyzer(db *database.DB, cfg *config.Config, importID util.FixedString, minTS, maxTS, minTSBeacon, maxTSBeacon time.Time, useCurrentTime bool, skipBeaconing bool) (*Analyzer, error) {

	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)
	networkSize, err := db.GetNetworkSize(minTS) // use true min TS for network size
	if err != nil {
		return nil, err
	}
	var firstSeenMaxTS time.Time
	if !useCurrentTime {
		firstSeenMaxTS = maxTS
	}

	workers := int(math.Floor(math.Max(4, float64(runtime.NumCPU())/2)))
	return &Analyzer{
		Database:        db,
		Config:          cfg,
		ImportID:        importID,
		AnalysisWorkers: workers,
		WriterWorkers:   workers,
		useCurrentTime:  useCurrentTime,
		maxTS:           maxTS,
		minTS:           minTS,
		maxTSBeacon:     maxTSBeacon,
		minTSBeacon:     minTSBeacon,
		firstSeenMaxTS:  firstSeenMaxTS,
		skipBeaconing:   skipBeaconing,
		networkSize:     networkSize,
		UconnChan:       make(chan AnalysisResult),
		writer:          database.NewBulkWriter(db, cfg, workers, db.GetSelectedDB(), "threat_mixtape", "INSERT INTO {database:Identifier}.threat_mixtape", limiter, false),
	}, nil
}

func (analyzer *Analyzer) Analyze() error {
	logger := zlog.GetLogger()

	// log the start time of the analysis
	start := time.Now()
	logger.Debug().Msg("Starting Analysis")

	// create an error group to manage the analysis threads
	analysisErrGroup, ctx := errgroup.WithContext(context.Background())

	// create analysis calculation workers
	for i := 0; i < analyzer.AnalysisWorkers; i++ {
		analysisErrGroup.Go(func() error {
			err := analyzer.runAnalysis()
			return err
		})
	}

	// create analysis writer workers
	for i := 0; i < analyzer.WriterWorkers; i++ {
		analyzer.writer.Start(i)
	}

	// start spagooper to feed anlysis threads
	err := analyzer.Spagoop(ctx)
	if err != nil {
		return fmt.Errorf("could not perform spagoop analysis: %w", err)
	}

	// wait for all analysis threads to finish
	if err := analysisErrGroup.Wait(); err != nil {
		logger.Fatal().Err(err).Msg("could not perform beacon analysis")
		return err
	}

	// close the mixtape writer
	analyzer.writer.Close()

	// log the end time of the analysis
	end := time.Now()
	diff := time.Since(start)
	logger.Info().Str("elapsed_time", diff.String()).Time("analysis_began", start).Time("analysis_finished", end).Msg("Finished Analysis! 🎉")

	return nil
}

func (analyzer *Analyzer) runAnalysis() error {
	logger := zlog.GetLogger()

	// loop over the uconn channel to process each entry
	for entry := range analyzer.UconnChan {
		// create a new mixtape entry to store the analysis results
		mixtape := &ThreatMixtape{
			AnalyzedAt:     analyzer.Database.ImportStartedAt.Truncate(time.Microsecond),
			ImportID:       analyzer.ImportID,
			AnalysisResult: entry,
			BeaconType:     entry.BeaconType,
			NetworkSize:    analyzer.networkSize,
		}

		// set the first seen historical value
		firstSeenHistorical, replaced := util.ValidateTimestamp(entry.FirstSeenHistorical)
		if replaced {
			logger.Debug().
				Str("src", entry.Src.String()).
				Str("dst", entry.Dst.String()).
				Str("missing_host_count", fmt.Sprint(entry.MissingHostCount)).
				Str("fqdn", entry.FQDN).Msg("historical first seen timestamp was missing")
		}

		// if the last seen timestamp was not valid, then this entry cannot be inserted into the mixtape
		// because modifiers require linking up with the last seen date
		// this should log a warning as this is a bugs
		lastSeen, replaced := util.ValidateTimestamp(entry.LastSeen)
		if replaced {
			logger.Debug().
				Str("src", entry.Src.String()).
				Str("dst", entry.Dst.String()).
				Str("missing_host_count", fmt.Sprint(entry.MissingHostCount)).
				Str("fqdn", entry.FQDN).Msg("last seen timestamp was missing")
		}

		mixtape.FirstSeenHistorical = firstSeenHistorical
		mixtape.LastSeen = lastSeen

		hasThreatIndicator := false

		// C2 OVER DNS
		if entry.TLD != "" && entry.SubdomainCount > 0 {
			// run c2 over dns analysis on entry if the TLD is a known c2 domain
			c2OverDNSScore := calculateBucketedScore(float64(entry.SubdomainCount), analyzer.Config.Scoring.C2ScoreThresholds)

			hash, err := util.NewFixedStringHash(entry.TLD)
			if err != nil {
				logger.Debug().Str("src", entry.Src.String()).Str("fqdn", entry.FQDN).Msg("could not create hash from TLD")
			}
			mixtape.Hash = hash
			mixtape.FQDN = entry.TLD
			if entry.SubdomainCount >= uint64(analyzer.Config.Scoring.C2ScoreThresholds.Base) {
				hasThreatIndicator = true
				mixtape.C2OverDNSScore = c2OverDNSScore
				// run c2 over dns direct connection analysis
				if mixtape.HasC2OverDNSDirectConnectionsModifier {
					mixtape.C2OverDNSDirectConnScore = analyzer.Config.Modifiers.C2OverDNSDirectConnScoreIncrease
				}
			}

		} else {

			// ALL OTHER THREAT INDICATORS
			// Run beaconing as long as there are min/max beacon timestamps
			if !analyzer.skipBeaconing {
				// run beacon analysis on entry if there are enough unique connections and the overall connection count is less than a strobe (1 connection per second)

				if entry.TSUnique >= uint64(analyzer.Config.Scoring.Beacon.UniqueConnectionThreshold) && entry.Count < 86400 {
					beacon, err := analyzer.analyzeBeacon(&entry)
					if err != nil {
						continue // all the errors will get logged in the beacon analyzer so we get a line number
					}
					beaconThreatScore := calculateBucketedScore(float64(beacon.Score*100), analyzer.Config.Scoring.Beacon.ScoreThresholds)
					hasThreatIndicator = true
					mixtape.Beacon = beacon
					mixtape.BeaconThreatScore = beaconThreatScore
				}
			}

			// run long connection analysis on entry if the total duration is greater than the minimum duration threshold
			if entry.TotalDuration >= float64(analyzer.Config.Scoring.LongConnectionScoreThresholds.Base) {
				longConnScore := calculateBucketedScore(entry.TotalDuration, analyzer.Config.Scoring.LongConnectionScoreThresholds)
				hasThreatIndicator = true
				mixtape.LongConnScore = longConnScore
			}

			// record entry as a strobe if the overall connection count meets the strobe threshold (1 connection per second)
			if entry.Count >= 86400 {
				hasThreatIndicator = true
				mixtape.Strobe = true
				mixtape.StrobeScore = analyzer.Config.Scoring.StrobeImpact.Score
			}

			// MODIFIERS
			// due to performance impact, these modifiers are scored here instead of in the modifier package
			// MISSING HOST HEADER MODIFIER
			if entry.MissingHostCount > 0 {
				mixtape.MissingHostHeaderScore = analyzer.Config.Modifiers.MissingHostCountScoreIncrease
			}

			// Threat Intel Data Size Score
			if entry.OnThreatIntel {
				if entry.TotalBytes >= uint64(analyzer.Config.Modifiers.ThreatIntelDataSizeThreshold) {
					mixtape.ThreatIntelDataSizeScore = analyzer.Config.Modifiers.ThreatIntelScoreIncrease
				}
			}

		}

		if hasThreatIndicator {

			// Modifiers that apply to all connection types
			// first seen scoring
			// use the current time to score against unless useCurrentTime is false
			relativeTime := util.GetRelativeFirstSeenTimestamp(analyzer.useCurrentTime, analyzer.firstSeenMaxTS)
			timeSince := relativeTime.Sub(entry.FirstSeenHistorical)
			daysSinceFirstSeen := float64(timeSince.Hours() / 24)

			// Historical First Seen Scoring
			// only apply to rolling datasets
			if analyzer.Database.Rolling {
				if daysSinceFirstSeen <= analyzer.Config.Modifiers.FirstSeenIncreaseThreshold {
					mixtape.FirstSeenScore = analyzer.Config.Modifiers.FirstSeenScoreIncrease
				} else if daysSinceFirstSeen >= analyzer.Config.Modifiers.FirstSeenDecreaseThreshold {
					mixtape.FirstSeenScore = -1 * analyzer.Config.Modifiers.FirstSeenScoreDecrease
				}
			}

			// Prevalence Scoring
			if entry.Prevalence <= analyzer.Config.Modifiers.PrevalenceIncreaseThreshold {
				mixtape.PrevalenceScore = analyzer.Config.Modifiers.PrevalenceScoreIncrease
			} else if entry.Prevalence >= analyzer.Config.Modifiers.PrevalenceDecreaseThreshold {
				mixtape.PrevalenceScore = -1 * analyzer.Config.Modifiers.PrevalenceScoreDecrease
			}

			// record entry as a threat intel if the entry is marked as threat intel
			if entry.OnThreatIntel {
				mixtape.ThreatIntel = true
				mixtape.ThreatIntelScore = analyzer.Config.Scoring.ThreatIntelImpact.Score
			}

			// check to see if any of the workers cancelled before sending another entry to the writer
			analyzer.writer.WriteChannel <- mixtape
		}
	}

	return nil
}

func calculateBucketedScore(value float64, thresholds config.ScoreThresholds) float64 {
	base := float64(thresholds.Base)
	low := float64(thresholds.Low)
	medium := float64(thresholds.Med)
	high := float64(thresholds.High)

	// convert category scores to integers for calculation
	noneScore := config.NONE_CATEGORY_SCORE * 100
	lowScore := config.LOW_CATEGORY_SCORE * 100
	mediumScore := config.MEDIUM_CATEGORY_SCORE * 100
	highScore := config.HIGH_CATEGORY_SCORE * 100

	score := float64(0)

	// interpolate scores between the threat category bucket thresholds
	switch {
	// (Low)    1-4hrs
	case value < base:
		return 0
	case value < low:
		score = float64(noneScore + (value-base)/(low-base)*(lowScore-noneScore))
	// (Medium) 4-8hrs
	case value >= low && value < medium:
		score = float64(lowScore + (value-low)/(medium-low)*(mediumScore-lowScore))
	// (High)   8-12hrs+
	case value >= medium:
		// cap the maximum duration score value to the High category threshold because we're not scoring any higher than this
		cappedValue := math.Min(value, high)
		score = float64(mediumScore + (cappedValue-medium)/(high-medium)*(highScore-mediumScore))
	}
	return score / 100
}

// shouldHaveC2OverDNSDirectConnModifier returns true if no ips other than the ones in queriedby made connections to this domain
func shouldHaveC2OverDNSDirectConnModifier(directConns, queriedBy []net.IP) bool {
	if len(queriedBy) > 0 {
		queried := make(map[string]struct{})
		for _, ip := range queriedBy {
			queried[ip.String()] = struct{}{}
		}

		// check for any ips in direct conns that aren't in queried by
		for _, ip := range directConns {
			if _, ok := queried[ip.String()]; !ok {
				return false
			}
		}

	}
	// apply direct conn modifier if no ips other than the ones in queried by made connections to this domain
	return true
}
