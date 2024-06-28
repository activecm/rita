package analysis

import (
	"activecm/rita/config"
	"log"
	"testing"

	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	m.Run()
}

/* **** THREAT SCORE BUCKETS ****
Each Threat Indicator's score is placed into a categorical severity bucket.
Since the units of measurement for each threat indicator varies, we must
place the scores into buckets based on predefined thresholds for each bucket.

Each bucket has a set, non-configurable score that it applies to.
None:   0%
Low:    20%-40%
Medium: 41%-60%
High:   61%-80%
*/

func TestCalculateBucketedScore(t *testing.T) {
	// verify that the score is greater than zero when the none threshold is zero
	// (and the value is greater than zero)
	score := calculateBucketedScore(1, config.ScoreThresholds{Base: 0, Low: 5, Med: 10, High: 15})
	require.Greater(t, score, float32(0), "score must be greater than zero when the base threshold is zero & the value is greater than zero")

	// verify that the score is 20% if the none threshold and the value are zero
	// this allows configuration for any positive integer to score at least 20%
	score = calculateBucketedScore(0, config.ScoreThresholds{Base: 0, Low: 5, Med: 10, High: 15})
	require.InDelta(t, 0.2, score, 0.0001, "score must be 0.2 if the base threshold and the value are zero")

	cfg, err := config.ReadFileConfig(afero.NewOsFs(), "../config.hjson")
	require.NoError(t, err)

	type testCase struct {
		Name       string
		Thresholds config.ScoreThresholds
	}

	testCases := []testCase{
		{Name: "C2 Over DNS", Thresholds: cfg.Scoring.C2ScoreThresholds},
		{Name: "Long Connections", Thresholds: cfg.Scoring.LongConnectionScoreThresholds},
		{Name: "Beacons", Thresholds: cfg.Scoring.Beacon.ScoreThresholds},
	}

	for _, test := range testCases {
		base := float64(test.Thresholds.Base)
		low := float64(test.Thresholds.Low)
		medium := float64(test.Thresholds.Med)
		high := float64(test.Thresholds.High)

		t.Run(test.Name, func(t *testing.T) {
			score = calculateBucketedScore(base-1, test.Thresholds)
			require.InDelta(t, 0, score, 0.00001, "score should be zero when value is lower than the None bucket threshold")

			// verify score matches the low threshold bucket score
			score = calculateBucketedScore(base, test.Thresholds)
			require.InDelta(t, .20, score, 0.001, "score must match the base threshold bucket score")

			score = calculateBucketedScore(low-1, test.Thresholds)
			require.InDelta(t, .3995, score, 0.1, "score should be very close to the low threshold score if it is almost at the medium threshold")

			score = calculateBucketedScore(low, test.Thresholds)
			require.InDelta(t, .40, score, 0.001, "score must match the low threshold bucket score")

			betweenLowAndMedium := low + ((medium - low) / 2)
			score = calculateBucketedScore(betweenLowAndMedium, test.Thresholds)
			require.InDelta(t, .50, score, 0.1, "score should interpolate between the low and medium bucket")

			score = calculateBucketedScore(medium-1, test.Thresholds)
			require.InDelta(t, .5995, score, 0.1, "score should be very close to the medium threshold score if it is almost at the high threshold")

			score = calculateBucketedScore(medium, test.Thresholds)
			require.InDelta(t, .60, score, 0.001, "score must match the medium threshold bucket score")

			betweenMediumAndHigh := medium + ((high - medium) / 2)
			score = calculateBucketedScore(betweenMediumAndHigh, test.Thresholds)
			require.InDelta(t, .70, score, 0.1, "score should interpolate between the medium and high bucket")

			score = calculateBucketedScore(high-1, test.Thresholds)
			require.InDelta(t, .7995, score, 0.1, "score should be very close to the high threshold score if it is almost at the high threshold")

			score = calculateBucketedScore(high, test.Thresholds)
			require.InDelta(t, .80, score, 0.001, "score must match the high threshold bucket score")

			score = calculateBucketedScore(high*2, test.Thresholds)
			require.InDelta(t, .80, score, 0.001, "score must match the high threshold bucket score even if the value is larger than the high threshold")
		})
	}
}
