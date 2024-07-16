package analysis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetBeaconScore(t *testing.T) {
	// Define test cases
	tests := []struct {
		name          string
		tsScore       float64
		tsWeight      float64
		dsScore       float64
		dsWeight      float64
		durScore      float64
		durWeight     float64
		histScore     float64
		histWeight    float64
		expectedScore float64
		expectedError bool
	}{

		{
			name:          "Valid Scores and Weights",
			tsScore:       0.8,
			tsWeight:      0.2,
			dsScore:       0.7,
			dsWeight:      0.2,
			durScore:      0.6,
			durWeight:     0.3,
			histScore:     0.5,
			histWeight:    0.3,
			expectedScore: 0.63,
			expectedError: false,
		},
		{
			name:          "All Scores 1, All Weights Equal",
			tsScore:       1,
			tsWeight:      0.25,
			dsScore:       1,
			dsWeight:      0.25,
			durScore:      1,
			durWeight:     0.25,
			histScore:     1,
			histWeight:    0.25,
			expectedScore: 1,
			expectedError: false,
		},
		{
			name:          "All Ccores 1, All Weights Different",
			tsScore:       1,
			tsWeight:      0.1,
			dsScore:       1,
			dsWeight:      0.2,
			durScore:      1,
			durWeight:     0.3,
			histScore:     1,
			histWeight:    0.4,
			expectedScore: 1,
			expectedError: false,
		},
		{
			name:          "All Scores Different, All Weights Equal",
			tsScore:       0.1,
			tsWeight:      0.25,
			dsScore:       0.2,
			dsWeight:      0.25,
			durScore:      0.3,
			durWeight:     0.25,
			histScore:     0.4,
			histWeight:    0.25,
			expectedScore: 0.25,
			expectedError: false,
		},
		{
			name:       "All Scores Different, All Weights Different",
			tsScore:    0.1,
			tsWeight:   0.1,
			dsScore:    0.2,
			dsWeight:   0.2,
			durScore:   0.3,
			durWeight:  0.3,
			histScore:  0.4,
			histWeight: 0.4,
			// 0.1*0.1 + 0.2*0.2 + 0.3*0.3 + 0.4*0.4 = 0.01 + 0.04 + 0.09 + 0.16 = 0.30
			// (0.30*1000)/1000 = 0.30
			expectedScore: 0.30,
			expectedError: false,
		},
		{
			name:       "High precision scores and weights",
			tsScore:    0.111,
			tsWeight:   0.173,
			dsScore:    0.222,
			dsWeight:   0.325,
			durScore:   0.333,
			durWeight:  0.299,
			histScore:  0.444,
			histWeight: 0.203, // histWeight = 1 - (0.173 + 0.325 + 0.299) = 0.203
			// 0.111*0.173 + 0.222*0.325 + 0.333*0.299 + 0.444*0.203 = 0.019263 + 0.07215 + 0.099567 + 0.090132 = 0.281112
			// (0.281112*1000)/1000 = 0.281
			expectedScore: 0.281,
			expectedError: false,
		},
		{ // to check for rounding errors
			name:          "Sensitivity test for closely-valued scores and weights",
			tsScore:       0.1001,
			tsWeight:      0.249,
			dsScore:       0.1002,
			dsWeight:      0.251,
			durScore:      0.1003,
			durWeight:     0.250,
			histScore:     0.1004,
			histWeight:    0.250,
			expectedScore: 0.10025,
			expectedError: false,
		},
		{
			name:          "Only one active weight",
			tsScore:       0.25,
			tsWeight:      1,
			dsScore:       1,
			dsWeight:      0,
			durScore:      1,
			durWeight:     0,
			histScore:     1,
			histWeight:    0,
			expectedScore: 0.25,
			expectedError: false,
		},
		{
			name:          "Negative score input",
			tsScore:       -0.1,
			tsWeight:      0.25,
			dsScore:       0.5,
			dsWeight:      0.25,
			durScore:      0.5,
			durWeight:     0.25,
			histScore:     0.5,
			histWeight:    0.25,
			expectedError: true,
		},
		{
			name:          "Score greater than 1",
			tsScore:       1.1,
			tsWeight:      0.25,
			dsScore:       0.5,
			dsWeight:      0.25,
			durScore:      0.5,
			durWeight:     0.25,
			histScore:     0.5,
			histWeight:    0.25,
			expectedError: true,
		},
		{
			name:          "Negative weight input",
			tsScore:       0.5,
			tsWeight:      -0.1,
			dsScore:       0.5,
			dsWeight:      0.25,
			durScore:      0.5,
			durWeight:     0.25,
			histScore:     0.5,
			histWeight:    0.25,
			expectedError: true,
		},
		{
			name:          "Weight greater than 1",
			tsScore:       0.5,
			tsWeight:      1.1,
			dsScore:       0.5,
			dsWeight:      0.25,
			durScore:      0.5,
			durWeight:     0.25,
			histScore:     0.5,
			histWeight:    0.25,
			expectedError: true,
		},
		{
			name:          "Weights sum more than 1",
			tsScore:       0.5,
			tsWeight:      0.3,
			dsScore:       0.5,
			dsWeight:      0.3,
			durScore:      0.5,
			durWeight:     0.3,
			histScore:     0.5,
			histWeight:    0.3,
			expectedError: true,
		},
		{
			name:          "Valid weight but sum less than 1",
			tsScore:       0.5,
			tsWeight:      0.3,
			dsScore:       0.5,
			dsWeight:      0.3,
			durScore:      0.5,
			durWeight:     0.2,
			histScore:     0.5,
			histWeight:    0.1,
			expectedError: true,
		},
		{
			name:          "Weights sum to more than 1",
			tsScore:       0.5,
			tsWeight:      0.3,
			dsScore:       0.5,
			dsWeight:      0.3,
			durScore:      0.5,
			durWeight:     0.3,
			histScore:     0.5,
			histWeight:    0.2,
			expectedError: true,
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			score, err := getBeaconScore(test.tsScore, test.tsWeight, test.dsScore, test.dsWeight, test.durScore, test.durWeight, test.histScore, test.histWeight)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated score
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)
		})
	}
}

func TestGetTimestampScore(t *testing.T) {
	tests := []struct {
		name                         string
		tsList                       []uint32
		expectedScore                float64
		expectedSkew                 float64
		expectedMAD                  float64
		expectedUniqueIntervals      []int64
		expectedUniqueIntervalCounts []int64
		expectedTSMode               int64
		expectedTSModeCount          int64
		expectedError                bool
	}{
		{
			name:   "Simple Number List",
			tsList: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			// intervals between timestamps: 1, 1, 1, 1, 1, 1, 1, 1, 1
			expectedUniqueIntervals:      []int64{1},
			expectedUniqueIntervalCounts: []int64{9},
			expectedTSMode:               1,
			expectedTSModeCount:          9,
			// q1 = 1, q2 = 1, q3 = 1
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 1)) = median(0, 1, 0, 1, 0, 1, 0, 1, 0) = 0
			expectedMAD:   0, // MAD score = 1 - 0 = 1
			expectedScore: 1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError: false,
		},
		{
			name: "Connection with Perfect Intervals",
			// timestamps : 1517338924, 1517338924 + 60, 1517338924 + 120, 1517338924 + 180, 1517338924 + 240, 1517338924 + 300, 1517338924 + 360, 1517338924 + 420, 1517338924 + 480, 1517338924 + 540,
			tsList: []uint32{1517338924, 1517338984, 1517339044, 1517339104, 1517339164, 1517339224, 1517339284, 1517339344, 1517339404, 1517339464},
			// intervals between timestamps: 60, 60, 60, 60, 60, 60, 60, 60, 60
			expectedUniqueIntervals:      []int64{60},
			expectedUniqueIntervalCounts: []int64{9},
			expectedTSMode:               60,
			expectedTSModeCount:          9,
			// q1 = 60, q2 = 60, q3 = 60
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(60 - 60)) = 0
			expectedMAD:   0, // MAD score = 1 - 0 = 1
			expectedScore: 1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError: false,
		},
		{
			name: "Connection with Closely-Valued Intervals",
			// timestamps : 1517338924, 1517338924 + 98, 1517338924 + 98 + 99, 1517338924 + 98 + 99 + 99, 1517338924 + 98 + 99 + 99 + 100, 1517338924 + 98 + 99 + 99 + 100 + 100, 1517338924 + 98 + 99 + 99 + 100 + 100 + 100, 1517338924 + 98 + 99 + 99 + 100 + 100 + 100 + 101, 1517338924 + 98 + 99 + 99 + 100 + 100 + 100 + 101 + 101, 1517338924 + 98 + 99 + 99 + 100 + 100 + 100 + 101 + 101 + 102,
			tsList: []uint32{1517338924, 1517339022, 1517339121, 1517339220, 1517339320, 1517339420, 1517339520, 1517339621, 1517339722, 1517339824},
			// intervals between timestamps: 98, 99, 99, 100, 100, 100, 101, 101, 102
			expectedUniqueIntervals:      []int64{98, 99, 100, 101, 102},
			expectedUniqueIntervalCounts: []int64{1, 2, 3, 2, 1},
			expectedTSMode:               100,
			expectedTSModeCount:          3,
			// q1 = 99, q2 = 100, q3 = 101
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 100)) = median(1, 0, 0, 1, 1, 1, 2, 2, 3) = 1
			expectedMAD:   1,     // MAD score = 1 - (mad/median) = 1 - 1/100 = 0.99
			expectedScore: 0.995, // score = round(((1 + 0.99)/2)*1000)/1000 = 0.995
			expectedError: false,
		},
		{
			name: "Connection with Bi-Modal Intervals",
			// timestamps : 1517338924, 1517338924 + 98, 1517338924 + 98 + 300, 1517338924 + 98 + 300 + 98, 1517338924 + 98 + 300 + 98 + 300, 1517338924 + 98 + 300 + 98 + 300 + 98, 1517338924 + 98 + 300 + 98 + 300 + 98 + 300, 1517338924 + 98 + 300 + 98 + 300 + 98 + 300 + 98, 1517338924 + 98 + 300 + 98 + 300 + 98 + 300 + 98 + 300, 1517338924 + 98 + 300 + 98 + 300 + 98 + 300 + 98 + 300 + 98,
			tsList: []uint32{1517338924, 1517339022, 1517339322, 1517339420, 1517339720, 1517339818, 1517340118, 1517340216, 1517340516, 1517340614, 1517340914},
			// intervals between timestamps: 98, 300, 98, 300, 98, 300, 98, 300, 98
			expectedUniqueIntervals:      []int64{98, 300},
			expectedUniqueIntervalCounts: []int64{5, 5},
			expectedTSMode:               98,
			expectedTSModeCount:          5,
			// Quartiles:  {98 199 300}
			// q1 = 98, q2 = 199, q3 = 300
			// numerator = q3 + q1 - 2*q2 = 300 + 98 - 2*199 = 300 + 98 - 398 = 0
			// IQR = q3 - q1 = 300 - 98 = 202
			// Bowley Skewness = (Q3+Q1 – 2Q2) / (Q3 – Q1) = numerator / IQR
			// but if the denominator less than 10 or the median is equal to the lower or upper quartile, the skewness is zero
			// skewness = 0
			// skewness score = 1 - skewness = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 199)) = median(101, 100, 101, 100, 101, 100, 101, 100, 101) = 101
			// MAD score = 1 - (mad/median) = 1 - 101/199 = 0.492
			// score = round(((1 + 0.492)/2)*1000)/1000 = 0.746
			expectedSkew:  0,
			expectedMAD:   101,
			expectedScore: 0.746,
			expectedError: false,
		},
		{
			name:   "Connection with Random Intervals",
			tsList: []uint32{1517338924, 1517338925, 1517339224, 1517339249, 1517344224, 1517344314, 1517344316, 1517344358, 1517344858, 1517346358},
			// intervals between timestamps: 1, 299, 25, 4975, 90, 2, 42, 500, 1500
			expectedUniqueIntervals:      []int64{1, 2, 25, 42, 90, 299, 500, 1500, 4975},
			expectedUniqueIntervalCounts: []int64{1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedTSMode:               1,
			expectedTSModeCount:          1,
			// q1 = 13.5, q2 = 90, q3 = 1000
			// numerator = q3 + q1 - 2*q2 = 1000 + 13.5 - 2*90 = 1000 + 13.5 - 180 = 833.5
			// IQR = q3 - q1 = 1000 - 13.5 = 986.5
			// skewness = numerator / IQR = 833.5 / 986.5 = 0.845
			// skewness score = 1 - skewness = 1 - 0.845 = 0.155
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 90)) = median(89, 209, 65, 4885, 0, 8, 48, 410, 1410) = 89
			// score = round(((0.155 + 0.01111)/2)*1000)/1000 = 0.083
			expectedSkew:  0.845, // skewness score = 1 - 0.845 = 0.155
			expectedMAD:   89,    // MAD score = 1 - (mad/median) = 1 - 89/90 = 0.01111
			expectedScore: 0.083,
			expectedError: false,
		},
		{
			// should not happen in practice, since we query for connections with > 3 unique timestamps
			name:   "Connection with < 3 Non-Zero Intervals",
			tsList: []uint32{60, 60, 60, 60, 60, 60, 60, 60, 60},
			// intervals between timestamps: 0, 0, 0, 0, 0, 0, 0, 0
			expectedError: true,
		},
		{
			name:          "Length of Timestamp List < 4",
			tsList:        []uint32{1517338924, 1517338925},
			expectedError: true,
		},
		{
			name:          "Empty Input Slice",
			tsList:        []uint32{},
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			score, skew, mad, intervals, intervalCounts, mode, modeCount, err := getTimestampScore(test.tsList)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated debug values
			require.Equal(test.expectedUniqueIntervals, intervals, "Expected unique intervals to be %v, got %v", test.expectedUniqueIntervals, intervals)
			require.Equal(test.expectedUniqueIntervalCounts, intervalCounts, "Expected unique interval counts to be %v, got %v", test.expectedUniqueIntervalCounts, intervalCounts)
			require.Equal(test.expectedTSMode, mode, "Expected mode to be %v, got %v", test.expectedTSMode, mode)
			require.Equal(test.expectedTSModeCount, modeCount, "Expected mode count to be %v, got %v", test.expectedTSModeCount, modeCount)

			// check the calculated score values
			require.InDelta(test.expectedSkew, skew, 0.001, "Expected skew to be %v, got %v", test.expectedSkew, skew)
			require.InDelta(test.expectedMAD, mad, 0.001, "Expected MAD to be %v, got %v", test.expectedMAD, mad)
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)

		})
	}
}

func TestGetDataSizeScore(t *testing.T) {
	tests := []struct {
		name                     string
		bytesList                []float64
		expectedScore            float64
		expectedSkew             float64
		expectedMAD              float64
		expectedUniqueSizes      []int64
		expectedUniqueSizeCounts []int64
		expectedDSMode           int64
		expectedDSModeCount      int64
		expectedRange            int64
		expectedError            bool
	}{
		{
			name:                     "Simple Number List",
			bytesList:                []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedUniqueSizes:      []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedUniqueSizeCounts: []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedDSMode:           1,
			expectedDSModeCount:      1,
			expectedRange:            9, // 10 - 1 = 9
			// q1 = 3, q2 = 5.5, q3 = 8
			// numerator = q3 + q1 - 2*q2 = 8 + 3 - 2*5.5 = 8 + 3 - 11 = 0
			// IQR = q3 - q1 = 8 - 3 = 5
			// skewness = numerator / IQR = 0 / 5 = 0
			expectedSkew: 0, // skewness score = 1 - skewness = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 5.5)) = median(4.5, 3.5, 2.5, 1.5, 0.5, 0.5, 1.5, 2.5, 3.5, 4.5) = 2.5
			expectedMAD:   2.5, // MAD score = 1 - (mad/median) = 1 - 2.5/5.5 = 0.545454
			expectedScore: 0.773,
			expectedError: false,
		},
		{
			name:                     "Connection with Identical Sizes",
			bytesList:                []float64{60, 60, 60, 60, 60, 60, 60, 60, 60},
			expectedUniqueSizes:      []int64{60},
			expectedUniqueSizeCounts: []int64{9},
			expectedDSMode:           60,
			expectedDSModeCount:      9,
			expectedRange:            0, // 60 - 60 = 0
			expectedSkew:             0, // skewness score = 1 - 0 = 1
			expectedMAD:              0, // MAD score = 1 - 0 = 1
			expectedScore:            1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError:            false,
		},
		{
			name:                     "Connection with Closely-Valued Sizes",
			bytesList:                []float64{98, 99, 99, 100, 100, 100, 101, 101, 102},
			expectedUniqueSizes:      []int64{98, 99, 100, 101, 102},
			expectedUniqueSizeCounts: []int64{1, 2, 3, 2, 1},
			expectedDSMode:           100,
			expectedDSModeCount:      3,
			expectedSkew:             0, // skewness score = 1 - 0 = 1
			expectedMAD:              1, // MAD score = 1 - (mad/median) = 1 - 1/100 = 0.99
			expectedScore:            0.995,
			expectedError:            false,
		},
		{
			name:                     "Connection with Random Sizes",
			bytesList:                []float64{524885, 1, 5000, 98654, 50, 41, 965842, 3},
			expectedUniqueSizes:      []int64{1, 3, 41, 50, 5000, 98654, 524885, 965842},
			expectedUniqueSizeCounts: []int64{1, 1, 1, 1, 1, 1, 1, 1},
			expectedDSMode:           1, // if there are multiple modes, the first one in list is chosen
			expectedDSModeCount:      1,
			// q1 = 22, q2 = 2525, q3 = 311769.5
			// numerator = q3 + q1 - 2*q2 = 311769.5 + 22 - 2*2525 = 311769.5 + 22 - 5050 = 306741.5
			// IQR = q3 - q1 = 311769.5 - 22 = 311747.5
			// skewness = numerator / IQR = 306741.5 / 311747.5 = 0.984
			// skewness score = 1 - skewness = 1 - 0.984 = 0.016
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 2525)) = median(2475, 2475, 2484, 2522, 2524, 96129, 522360, 963317) = 2522+2524/2 = 2523
			expectedSkew:  0.984, // skewness score = 1 - 0.984 = 0.016
			expectedMAD:   2523,  // MAD score = 1 - (mad/median) = 1 - (2523/2525) = 0.000792079
			expectedScore: 0.008, // score = round(((0.016+0.000792079)/2)*1000)/1000 = 0.008
			expectedError: false,
		},
		{
			name:                     "Bytes List is Comprised of Only 0s",
			bytesList:                []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedUniqueSizes:      []int64{0},
			expectedUniqueSizeCounts: []int64{10},
			expectedDSMode:           0,
			expectedDSModeCount:      10,
			expectedSkew:             0,   // skewness score = 1 - 0 = 1
			expectedMAD:              0,   // MAD score = 0, since median < 1 and defaultMADScore for datasize scoring is 0
			expectedScore:            0.5, // score = round(((1 + 0)/2)*1000)/1000 = 0.5
			expectedError:            false,
		},
		// in practice we should have at least 4, since we require at least 4 connections to calculate the score
		{
			name:          "Length of Bytes List < 3",
			bytesList:     []float64{100, 200},
			expectedError: true,
		},
		{
			name:          "Empty Input Slice",
			bytesList:     []float64{},
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			score, skew, mad, sizes, sizeCounts, mode, modeCount, err := getDataSizeScore(test.bytesList)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated debug values
			require.Equal(test.expectedUniqueSizes, sizes, "Expected unique sizes to be %v, got %v", test.expectedUniqueSizes, sizes)
			require.Equal(test.expectedUniqueSizeCounts, sizeCounts, "Expected unique size counts to be %v, got %v", test.expectedUniqueSizeCounts, sizeCounts)
			require.InDelta(test.expectedDSMode, mode, 0.001, "Expected mode to be %v, got %v", test.expectedDSMode, mode)
			require.Equal(test.expectedDSModeCount, modeCount, "Expected mode count to be %v, got %v", test.expectedDSModeCount, modeCount)

			// check the calculated score values
			require.InDelta(test.expectedSkew, skew, 0.001, "Expected skew to be %v, got %v", test.expectedSkew, skew)
			require.InDelta(test.expectedMAD, mad, 0.001, "Expected MAD to be %v, got %v", test.expectedMAD, mad)
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)

		})
	}
}

func TestCalculateStatisticalScore(t *testing.T) {
	tests := []struct {
		name            string
		values          []float64
		defaultMadScore float64
		expectedScore   float64
		expectedSkew    float64
		expectedMAD     float64
		expectedError   bool
	}{
		{
			name:            "Simple Number List",
			values:          []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			defaultMadScore: 0,
			// q1 = 3, q2 = 5.5, q3 = 8
			// numerator = q3 + q1 - 2*q2 = 8 + 3 - 2*5.5 = 8 + 3 - 11 = 0
			// IQR = q3 - q1 = 8 - 3 = 5
			// skewness = numerator / IQR = 0 / 5 = 0
			// skewness score = 1 - skewness = 1 - 0 = 1
			expectedSkew: 0, // skewness score = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 5.5)) = median(4.5, 3.5, 2.5, 1.5, 0.5, 0.5, 1.5, 2.5, 3.5, 4.5) = 2.5
			expectedMAD:   2.5, // MAD score = 1 - (mad/median) = 1 - 2.5/5.5 = 0.545454
			expectedScore: 0.773,
			expectedError: false,
		},
		{
			name:            "Connection with Identical Intervals/Sizes",
			values:          []float64{60, 60, 60, 60, 60, 60, 60, 60, 60},
			defaultMadScore: 0,
			// q1 = 60, q2 = 60, q3 = 60
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(60 - 60)) = 0
			expectedMAD:   0, // MAD score = 1 - 0 = 1
			expectedScore: 1, // score = round(((1 + 1)/2)*1000)/1000 = 1
		},
		{
			name:   "Connection with Closely-Valued Intervals/Sizes",
			values: []float64{98, 99, 99, 100, 100, 100, 101, 101, 102},
			// q1 = 99, q2 = 100, q3 = 101
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 100)) = median(1, 0, 0, 1, 1, 1, 2, 2, 3) = 1
			expectedMAD: 1, // MAD score = 1 - (mad/median) = 1 - 1/100 = 0.99
			// score = round(((1 + 0.99)/2)*1000)/1000 = 0.995
			expectedScore: 0.995,
		},
		{
			name: "Connection with Random Intervals/Sizes",
			// timestamps : 1517338924, 1517338924 + 1, 1517338924 + 300, 1517338924 + 25, 1517338924 + 5000, 1517338924 + 100, 1517338924 + 1000, 1517338924 + 200, 1517338924 + 1500, 1517338924 + 3000,
			// intervals between timestamps: 1, 299, 25, 4975, 90, 900, 800, 500, 1500
			values:          []float64{1, 299, 25, 4975, 90, 2, 42, 500, 1500},
			defaultMadScore: 1,
			// q1 = 13.5, q2 = 90, q3 = 1000
			// numerator = q3 + q1 - 2*q2 = 1000 + 13.5 - 2*90 = 1000 + 13.5 - 180 = 833.5
			// IQR = q3 - q1 = 1000 - 13.5 = 986.5
			// skewness = numerator / IQR = 833.5 / 986.5 = 0.845
			// skewness score = 1 - skewness = 1 - 0.845 = 0.155
			expectedSkew: 0.845, // skewness score = 1 - 0.845 = 0.155
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 90)) = median(89, 209, 65, 4885, 0, 8, 48, 410, 1410) = 89
			expectedMAD:   89,    // MAD score = 1 - (mad/median) = 1 - 89/90 = 0.01111
			expectedScore: 0.083, // score = round(((0.155 + 0.01111)/2)*1000)/1000 = 0.083
			expectedError: false,
		},
		{
			name:            "Connection with Random Intervals/Sizes, defaultMadScore = 0",
			values:          []float64{524885, 1, 5000, 98654, 50, 41, 965842, 3},
			defaultMadScore: 0,
			// q1 = 22, q2 = 2525, q3 = 311769.5
			// numerator = q3 + q1 - 2*q2 = 311769.5 + 22 - 2*2525 = 311769.5 + 22 - 5050 = 306741.5
			// IQR = q3 - q1 = 311769.5 - 22 = 311747.5
			// skewness = numerator / IQR = 306741.5 / 311747.5 = 0.983
			expectedSkew: 0.983, // skewness score = 1 - skewness = 1 - 0.983 = 0.017
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 2525)) = median(252363, 2524, 2475, 2509, 2475, 2484, 96317, 2522) = 2523
			expectedMAD:   2523,  // MAD score = 1 - (mad/median) = 1 - (2523/2525) = 0.00079
			expectedScore: 0.009, // score = round(((0.017 + 0.00079)/2)*1000)/1000 = 0.009
			expectedError: false,
		},
		{
			// this will not happen in practice for the timestamps, since we use a list of non-zero intervals between timestamps
			name:            "Median == 0, defaultMadScore = 0",
			values:          []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			defaultMadScore: 0,
			expectedSkew:    0,   // skewness score = 1 - 0 = 1
			expectedMAD:     0,   // MAD score = 0, since median < 1 and defaultMADScore = 0
			expectedScore:   0.5, // score = round(((1 + 0)/2)*1000)/1000 = 0.5
			expectedError:   false,
		},
		{
			// this will not happen in practice for the timestamps, since we use a list of non-zero intervals between timestamps
			name:            "Median == 0, defaultMadScore = 1",
			values:          []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			defaultMadScore: 1,
			expectedSkew:    0, // skewness score = 1 - 0 = 1
			expectedMAD:     0, // MAD score = 1, since median < 1 and defaultMADScore = 1
			expectedScore:   1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError:   false,
		},
		{
			name:            "Median < 1, defaultMadScore = 0",
			values:          []float64{-1, -2, -3, -4, -5, -6, -7, -8, -9, -10},
			defaultMadScore: 0, // default score for bytes is zero
			// q1 = -3, q2 = -5.5, q3 = -8
			// numerator = q3 + q1 - 2*q2 = -8 + -3 - 2*-5.5 = -8 + -3 + 11 = 0
			// IQR = q3 - q1 = -8 - -3 = -5
			// skewness = numerator / IQR = 0 / -5 = 0
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - -5.5)) = median(4.5, 3.5, 2.5, 1.5, 0.5, 0.5, 1.5, 2.5, 3.5, 4.5) = 2.5
			expectedMAD:   2.5, // MAD score = 0 since median < 1 and defaultMADScore = 0
			expectedScore: 0.5, // score = round(((1 + 0)/2)*1000)/1000 = 0.5
			expectedError: false,
		},
		{
			name:            "Bowley's Skew Unreliable: Q1 == Q2",
			values:          []float64{7, 8, 7, 8, 7, 8, 7, 8, 7},
			defaultMadScore: 1,
			// q1 = 7, q2 = 7, q3 = 8 // skewness will not be calculated and stay at zero
			expectedSkew: 0, // skewness score = 1 - 0 = 1
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 7)) = median(0, 1, 0, 1, 0, 1, 0, 1, 0) = 0
			expectedMAD:   0, // MAD score = 1 since defaultMADScore = 1
			expectedScore: 1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError: false,
		},
		{
			name:            "Bowley's Skew Unreliable: Q2 == Q3",
			values:          []float64{1, 1, 2, 2, 2, 2},
			defaultMadScore: 1,
			// q1 = 1, q2 = 2, q3 = 2 // skewness will not be calculated and stay at zero
			expectedSkew: 0,
			// median absolute deviation = median(abs(x - median(x))) = median(abs(x - 2)) = median(1, 1, 0, 0, 0, 0) = 0
			expectedMAD:   0, // MAD score = 1 since defaultMADScore = 1
			expectedScore: 1, // score = round(((1 + 1)/2)*1000)/1000 = 1
			expectedError: false,
		},
		{
			name:            "Empty Input Slice",
			values:          []float64{},
			defaultMadScore: 0,
			expectedSkew:    0,
			expectedMAD:     0,
			expectedScore:   0,
			expectedError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			score, skew, mad, err := calculateStatisticalScore(test.values, test.defaultMadScore)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated values
			require.InDelta(test.expectedSkew, skew, 0.001, "Expected skew to be %v, got %v", test.expectedSkew, skew)
			require.InDelta(test.expectedMAD, mad, 0.001, "Expected MAD to be %v, got %v", test.expectedMAD, mad)
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)

		})
	}
}

func TestGetDurationScore(t *testing.T) {

	tests := []struct {
		name                  string
		datasetMin            int64
		datasetMax            int64
		histMin               int64
		histMax               int64
		totalBars             int
		longestConsecutiveRun int
		minHoursThreshold     int
		idealConsistencyHours int
		expectedCoverage      float64
		expectedConsistency   float64
		expectedScore         float64
		expectedError         bool
	}{
		{
			name:                  "Full Dataset Coverage, Full Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924,
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             24,
			longestConsecutiveRun: 24,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      1,
			expectedConsistency:   1,
			expectedScore:         1,
			expectedError:         false,
		},
		{
			name:                  "Full Dataset Coverage, Min Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924,
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             6,
			longestConsecutiveRun: 0,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      1,
			expectedConsistency:   0,
			expectedScore:         1,
			expectedError:         false,
		},
		{
			name:                  "First Half Dataset Coverage, Min Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 12*3600, // 12 hours later
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             6,
			longestConsecutiveRun: 0,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.5,
			expectedConsistency:   0,
			expectedScore:         0.5,
			expectedError:         false,
		},
		{
			name:                  "Last Half Dataset Coverage, Min Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924,
			histMax:               1517338924 + 12*3600, // 12 hours later
			totalBars:             6,
			longestConsecutiveRun: 0,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.5,
			expectedConsistency:   0,
			expectedScore:         0.5,
			expectedError:         false,
		},
		{
			name:                  "3/4 Dataset Coverage, Min Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 6*3600,  // 6 hours later
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             6,
			longestConsecutiveRun: 0,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.75,
			expectedConsistency:   0,
			expectedScore:         0.75,
			expectedError:         false,
		},
		{
			name:                  "Max Consistency",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 12*3600, // 12 hours later
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             12,
			longestConsecutiveRun: 12,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.5,
			expectedConsistency:   1,
			expectedScore:         1,
			expectedError:         false,
		},
		{
			name:                  "Max Consistency with min TotalBars (6)",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 12*3600, // 12 hours later
			histMax:               1517338924 + 18*3600, // 18 hours later
			totalBars:             6,
			longestConsecutiveRun: 6,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.25,
			expectedConsistency:   0.5,
			expectedScore:         0.5,
			expectedError:         false,
		},
		{
			name:                  "Average Consistency with Average Coverage",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 6*3600,  // 6 hours later
			histMax:               1517338924 + 18*3600, // 18 hours later
			totalBars:             12,
			longestConsecutiveRun: 6,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0.5,
			expectedConsistency:   0.5,
			expectedScore:         0.5,
			expectedError:         false,
		},
		{
			name:                  "TotalBars < MinHoursThreshold",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924 + 6*3600,  // 6 hours later
			histMax:               1517338924 + 18*3600, // 18 hours later
			totalBars:             3,
			longestConsecutiveRun: 1,
			minHoursThreshold:     6,
			idealConsistencyHours: 12,
			expectedCoverage:      0,
			expectedConsistency:   0,
			expectedScore:         0,
			expectedError:         false,
		},
		{
			name:                  "Ideal Consistency Hours < 1",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924,
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             12,
			longestConsecutiveRun: 6,
			minHoursThreshold:     6,
			idealConsistencyHours: 0,
			expectedCoverage:      0,
			expectedConsistency:   0,
			expectedScore:         0,
			expectedError:         true,
		},
		{
			name:                  "Min Hours Threshold < 1",
			datasetMin:            1517338924,
			datasetMax:            1517338924 + 24*3600, // 24 hours later
			histMin:               1517338924,
			histMax:               1517338924 + 24*3600, // 24 hours later
			totalBars:             12,
			longestConsecutiveRun: 6,
			minHoursThreshold:     0,
			idealConsistencyHours: 12,
			expectedCoverage:      0,
			expectedConsistency:   0,
			expectedScore:         0,
			expectedError:         true,
		},
		{
			name:                  "Dataset Min > Dataset Max",
			datasetMin:            1,
			datasetMax:            0,
			histMin:               0,
			histMax:               1,
			totalBars:             6,
			longestConsecutiveRun: 12,
			expectedCoverage:      0,
			expectedConsistency:   0,
			expectedScore:         0,
			expectedError:         true,
		},
		{
			name:                  "Hist Min > Hist Max",
			datasetMin:            0,
			datasetMax:            1,
			histMin:               1,
			histMax:               0,
			totalBars:             6,
			longestConsecutiveRun: 12,
			expectedCoverage:      0,
			expectedConsistency:   0,
			expectedScore:         0,
			expectedError:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			coverage, consistency, score, err := getDurationScore(test.datasetMin, test.datasetMax, test.histMin, test.histMax, test.totalBars, test.longestConsecutiveRun, test.minHoursThreshold, test.idealConsistencyHours)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", false, err)

			// check the calculated values
			require.InDelta(test.expectedConsistency, consistency, 0.001, "Expected consistency to be %v, got %v", test.expectedConsistency, consistency)
			require.InDelta(test.expectedCoverage, coverage, 0.001, "Expected coverage to be %v, got %v", test.expectedCoverage, coverage)
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)
		})
	}
}

func TestGetHistogramScore(t *testing.T) {

	tests := []struct {
		name                       string
		datasetMin                 int64
		datasetMax                 int64
		tsList                     []uint32
		modalSensitivity           float64
		bimodalOutlierRemoval      int
		minHoursForBimodalAnalysis int
		beaconTimeSpan             int
		expectedBinEdges           []float64
		expectedHistogram          []int
		expectedFreqCount          map[int32]int32
		expectedTotalBars          int
		expectedLongestRun         int
		expectedScore              float64
		expectedError              bool
	}{
		{
			name:       "Simple Number List",
			datasetMin: 1,
			datasetMax: 11,
			tsList: []uint32{
				1,
				2, 2,
				3, 3, 3,
				4, 4, 4, 4,
				5, 5, 5, 5, 5,
				6, 6, 6, 6, 6, 6,
				7, 7, 7, 7, 7, 7, 7,
				8, 8, 8, 8, 8, 8, 8, 8,
				9, 9, 9, 9, 9, 9, 9, 9, 9,
				10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
			},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 6,
			beaconTimeSpan:             10,
			expectedBinEdges:           []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			expectedHistogram:          []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedFreqCount:          map[int32]int32{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1},
			expectedTotalBars:          10,
			expectedLongestRun:         10,
			expectedScore:              0.478,
			expectedError:              false,
		},
		{
			name:                       "Connection with Regular Intervals",
			datasetMin:                 1517338924,
			datasetMax:                 1517338924 + 24*3600, // 24 hours later
			tsList:                     []uint32{1517338924, 1517338924 + 1*3600, 1517338924 + 2*3600, 1517338924 + 3*3600, 1517338924 + 4*3600, 1517338924 + 5*3600, 1517338924 + 6*3600, 1517338924 + 7*3600, 1517338924 + 8*3600, 1517338924 + 9*3600, 1517338924 + 10*3600, 1517338924 + 11*3600, 1517338924 + 12*3600, 1517338924 + 13*3600, 1517338924 + 14*3600, 1517338924 + 15*3600, 1517338924 + 16*3600, 1517338924 + 17*3600, 1517338924 + 18*3600, 1517338924 + 19*3600, 1517338924 + 20*3600, 1517338924 + 21*3600, 1517338924 + 22*3600, 1517338924 + 23*3600},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 11,
			beaconTimeSpan:             24,
			// total edges: 24 + 1 = 25
			// step: (maxTS - minTS) / total edges - 1 = 24*3600 / 24 = 3600
			// first edge: 1517338924, last edge: 1517338924 + 24*3600
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			expectedBinEdges:   []float64{1517338924, 1517342524, 1517346124, 1517349724, 1517353324, 1517356924, 1517360524, 1517364124, 1517367724, 1517371324, 1517374924, 1517378524, 1517382124, 1517385724, 1517389324, 1517392924, 1517396524, 1517400124, 1517403724, 1517407324, 1517410924, 1517414524, 1517418124, 1517421724, 1517425324},
			expectedHistogram:  []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedFreqCount:  map[int32]int32{1: 24},
			expectedTotalBars:  24,
			expectedLongestRun: 24,
			expectedScore:      1,
			expectedError:      false,
		},
		{
			name:                       "Connection with Closely-Valued Timestamps",
			datasetMin:                 98,
			datasetMax:                 102,
			tsList:                     []uint32{98, 99, 99, 100, 100, 100, 101, 101, 102},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 6,
			beaconTimeSpan:             8,
			// total edges: 8 + 1 = 9
			// step: (maxTS - minTS) / total edges - 1 = 102 - 98 / 8 = 4/8 = 0.5
			// first edge: 98, last edge: 102
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			expectedBinEdges:   []float64{98, 98.5, 99, 99.5, 100, 100.5, 101, 101.5, 102},
			expectedHistogram:  []int{1, 0, 2, 0, 3, 0, 2, 1},
			expectedFreqCount:  map[int32]int32{1: 2, 2: 2, 3: 1},
			expectedTotalBars:  5,
			expectedLongestRun: 3,
			// MEAN = 1.125, SD = 1.05327, CV = 0.936, cvScore = 1 - 0.936 = 0.064
			expectedScore: 0.064, // score = max(cv score, bimodal fit score) = max (0.064, 0) = 0.064
			expectedError: false,
		},
		{
			name:                       "Connection with Random Intervals, CV > 1",
			datasetMin:                 0,
			datasetMax:                 1000000,
			tsList:                     []uint32{524885, 1, 5000, 98654, 50, 41, 965842, 3, 12001, 200400, 104001, 199999},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 6,
			beaconTimeSpan:             10,
			// total edges: 10 + 1 = 11
			// step: (maxTS - minTS) / total edges - 1 = 1000000 / 10 = 100000
			// first edge: 0, last edge: 1000000
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			expectedBinEdges:   []float64{0, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000, 1000000},
			expectedHistogram:  []int{7, 2, 1, 0, 0, 1, 0, 0, 0, 1},
			expectedFreqCount:  map[int32]int32{1: 3, 2: 1, 7: 1},
			expectedTotalBars:  5,
			expectedLongestRun: 4,
			// mean = 1.2, sd = 2.0396, cv = sd / abs(mean) = 2.0396 / 1.2 = 1.6997, cvScore = 0 (since cv > 1)
			expectedScore: 0, // score = max(cv score, bimodal fit score) = max (0, 0) = 0
			expectedError: false,
		},
		{
			name:                       "Connection with Bimodal Histogram",
			datasetMin:                 0,
			datasetMax:                 100,
			tsList:                     []uint32{1, 2, 3, 4, 15, 21, 22, 23, 24, 35, 41, 42, 43, 44, 55, 61, 62, 63, 64, 75, 81, 82, 83, 84, 95},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 6,
			beaconTimeSpan:             10,
			expectedBinEdges:           []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			expectedHistogram:          []int{4, 1, 4, 1, 4, 1, 4, 1, 4, 1},
			expectedFreqCount:          map[int32]int32{1: 5, 4: 5},
			expectedTotalBars:          10,
			expectedLongestRun:         10,
			// mean = 2.5, sd = 1.5, cv = sd / abs(mean) = 1.5 / 2.5 = 0.6, cvScore = 1 - 0.6 = 0.4
			expectedScore: 1, // score = max(cv score, bimodal fit score) = max (0.4, 1) = 1
			expectedError: false,
		},
		{
			name:                       "Connection with Histogram that has Gaps and a Wraparound Timestamp Run",
			datasetMin:                 0,
			datasetMax:                 250,
			tsList:                     []uint32{10, 20, 100, 110, 110, 220},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 6,
			beaconTimeSpan:             5,
			expectedBinEdges:           []float64{0, 50, 100, 150, 200, 250},
			expectedHistogram:          []int{2, 0, 3, 0, 1},
			expectedFreqCount:          map[int32]int32{1: 1, 2: 1, 3: 1},
			expectedTotalBars:          3,
			expectedLongestRun:         2,
			// mean = 1.2, sd = 1.1662, cv = sd / abs(mean) = 1.1662 / 1.2 = 0.9718, cvScore = 1 - 0.9718 = 0.0282
			expectedScore: 0.028, // score = max(cv score, bimodal fit score) = max (0.028, 0) = 0.028
			expectedError: false,
		},
		{
			name:                       "Connection with Single Bar Histogram",
			datasetMin:                 1517338924,
			datasetMax:                 1517338924 + 24*3600, // 24 hours later
			tsList:                     []uint32{1517338924, 1517338924 + 60, 1517338924 + 120, 1517338924 + 180, 1517338924 + 240, 1517338924 + 300, 1517338924 + 360, 1517338924 + 420, 1517338924 + 480, 1517338924 + 540},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 11,
			beaconTimeSpan:             24,
			expectedBinEdges:           []float64{1517338924, 1517342524, 1517346124, 1517349724, 1517353324, 1517356924, 1517360524, 1517364124, 1517367724, 1517371324, 1517374924, 1517378524, 1517382124, 1517385724, 1517389324, 1517392924, 1517396524, 1517400124, 1517403724, 1517407324, 1517410924, 1517414524, 1517418124, 1517421724, 1517425324},
			expectedHistogram:          []int{10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedFreqCount:          map[int32]int32{10: 1},
			expectedTotalBars:          1,
			expectedLongestRun:         1,
			expectedScore:              0,
			expectedError:              false,
		},
		{
			// this should not happen in practice since min hours for bimodal analysis is vetted when the config is loaded.
			// this is to ensure that the bimodal fit score is not calculated for histograms with too few bars, as in that case
			// a histogram with 1-2 bars will always be given a high bimoal fit score as it technically has 1-2 modes
			name:                       "Connection with Single Bar Histogram and MinHoursForBimodal Analysis Set to < 3",
			datasetMin:                 1517338924,
			datasetMax:                 1517338924 + 24*3600, // 24 hours later
			tsList:                     []uint32{1517338924, 1517338924 + 60, 1517338924 + 120, 1517338924 + 180, 1517338924 + 240, 1517338924 + 300, 1517338924 + 360, 1517338924 + 420, 1517338924 + 480, 1517338924 + 540},
			modalSensitivity:           0.05,
			bimodalOutlierRemoval:      1,
			minHoursForBimodalAnalysis: 1, // < 3
			beaconTimeSpan:             24,
			expectedBinEdges:           []float64{1517338924, 1517342524, 1517346124, 1517349724, 1517353324, 1517356924, 1517360524, 1517364124, 1517367724, 1517371324, 1517374924, 1517378524, 1517382124, 1517385724, 1517389324, 1517392924, 1517396524, 1517400124, 1517403724, 1517407324, 1517410924, 1517414524, 1517418124, 1517421724, 1517425324},
			expectedHistogram:          []int{10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedFreqCount:          map[int32]int32{10: 1},
			expectedTotalBars:          1,
			expectedLongestRun:         1,
			expectedScore:              0, // this would be 1 if minHoursForBimodalAnalysis was not overridden
			expectedError:              false,
		},

		{
			name:          "Empty Timestamp List",
			datasetMin:    0,
			datasetMax:    10,
			tsList:        []uint32{},
			expectedError: true,
		},
		{
			name:          "Dataset Min > Dataset Max",
			datasetMin:    1,
			datasetMax:    0,
			tsList:        []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedError: true,
		},
		{
			name:          "Dataset Min == Dataset Max",
			datasetMin:    1,
			datasetMax:    1,
			tsList:        []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			freqList, freqCount, totalBars, longestRun, score, err := getHistogramScore(test.datasetMin, test.datasetMax, test.tsList, test.modalSensitivity, test.bimodalOutlierRemoval, test.minHoursForBimodalAnalysis, test.beaconTimeSpan)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", false, err)

			// check the calculated values
			require.Equal(test.expectedHistogram, freqList, "Expected frequency list to be %v, got %v", test.expectedHistogram, freqList)
			require.Equal(test.expectedFreqCount, freqCount, "Expected frequency count to be %v, got %v", test.expectedFreqCount, freqCount)
			require.Equal(test.expectedTotalBars, totalBars, "Expected total bars to be %v, got %v", test.expectedTotalBars, totalBars)
			require.Equal(test.expectedLongestRun, longestRun, "Expected longest run to be %v, got %v", test.expectedLongestRun, longestRun)
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)

		})
	}

}
func TestCalculateBowleySkewness(t *testing.T) {

	testCases := []struct {
		name                       string
		intervalsBetweenTimestamps []float64
		expectedSkewness           float64
		expectedSkewnessScore      float64
		expectedError              bool
	}{

		{
			name:                       "Simple Number List",
			intervalsBetweenTimestamps: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedSkewness:           0,
			expectedSkewnessScore:      1,
			expectedError:              false,
		},
		{
			name: "Connection with Perfect Intervals",
			// in this case bowley's skew would actually not be calculated since q1 == q2 == q3 and the score would default to 100%
			// timestamps : 1517338924, 1517338924 + 60, 1517338924 + 120, 1517338924 + 180, 1517338924 + 240, 1517338924 + 300, 1517338924 + 360, 1517338924 + 420, 1517338924 + 480, 1517338924 + 540,
			// intervals between timestamps: 60, 60, 60, 60, 60, 60, 60, 60, 60
			intervalsBetweenTimestamps: []float64{60, 60, 60, 60, 60, 60, 60, 60, 60},
			expectedSkewness:           0,
			expectedSkewnessScore:      1,
			expectedError:              false,
		},
		{
			name:                       "Connection with Regular Intervals",
			intervalsBetweenTimestamps: []float64{98, 99, 99, 100, 100, 100, 101, 101, 102},
			// q1 = 99, q2 = 100, q3 = 101
			// numerator = q3 + q1 - 2*q2 = 101 + 99 - 2*100 = 101 + 99 - 200 = 0
			// IQR = q3 - q1 = 101 - 99 = 2
			// skewness = numerator / IQR = 0 / 2 = 0
			// skewness score = 1 - skewness = 1 - 0 = 1
			expectedSkewness:      0,
			expectedSkewnessScore: 1,
			expectedError:         false,
		},
		{
			name:                       "Connection with Random Intervals Sorted",
			intervalsBetweenTimestamps: []float64{1, 2, 25, 42, 90, 299, 500, 1500, 4975},
			// q1 = 13.5, q2 = 90, q3 = 1000
			// numerator = q3 + q1 - 2*q2 = 1000 + 13.5 - 2*90 = 1000 + 13.5 - 180 = 833.5
			// IQR = q3 - q1 = 1000 - 13.5 = 986.5
			// skewness = numerator / IQR = 833.5 / 986.5 = 0.845
			// skewness score = 1 - skewness = 1 - 0.845 = 0.155
			expectedSkewness:      0.845,
			expectedSkewnessScore: 0.155,
			expectedError:         false,
		},
		{
			name: "Connection with Random Intervals Unsorted",
			// timestamps : 1517338924, 1517338924 + 1, 1517338924 + 300, 1517338924 + 25, 1517338924 + 5000, 1517338924 + 100, 1517338924 + 1000, 1517338924 + 200, 1517338924 + 1500, 1517338924 + 3000,
			// intervals between timestamps: 1, 299, 25, 4975, 90, 900, 800, 500, 1500
			intervalsBetweenTimestamps: []float64{1, 299, 25, 4975, 90, 2, 42, 500, 1500},
			// q1 = 13.5, q2 = 90, q3 = 1000
			// numerator = q3 + q1 - 2*q2 = 1000 + 13.5 - 2*90 = 1000 + 13.5 - 180 = 833.5
			// IQR = q3 - q1 = 1000 - 13.5 = 986.5
			// skewness = numerator / IQR = 833.5 / 986.5 = 0.845
			// skewness score = 1 - skewness = 1 - 0.845 = 0.155
			expectedSkewness:      0.845,
			expectedSkewnessScore: 0.155,
			expectedError:         false,
		},
		{
			name:                       "Connection with Random Intervals Unsorted 2",
			intervalsBetweenTimestamps: []float64{524885, 1, 5000, 98654, 50, 41, 965842, 3},
			// q1 = 22, q2 = 2525, q3 = 311769.5
			// numerator = q3 + q1 - 2*q2 = 311769.5 + 22 - 2*2525 = 311769.5 + 22 - 5050 = 306741.5
			// IQR = q3 - q1 = 311769.5 - 22 = 311747.5
			// skewness = numerator / IQR = 306741.5 / 311747.5 = 0.983
			// skewness score = 1 - skewness = 1 - 0.983 = 0.017
			expectedSkewness:      0.983,
			expectedSkewnessScore: 0.017,
			expectedError:         false,
		},
		{
			name:                       "Bowley's Skew Unreliable: Q1 == Q2",
			intervalsBetweenTimestamps: []float64{7, 8, 7, 8, 7, 8, 7, 8, 7},
			// q1 = 7, q2 = 7, q3 = 8
			expectedSkewness:      0, // skewness will not be calculated and stay at zero
			expectedSkewnessScore: 1, // score will stay at the deafault 100%
			expectedError:         false,
		},
		{
			name:                       "Bowley's Skew Unreliable: Q2 == Q3",
			intervalsBetweenTimestamps: []float64{1, 1, 2, 2, 2, 2},
			// q1 = 1, q2 = 2, q3 = 2
			expectedSkewness:      0, // skewness will not be calculated and stay at zero
			expectedSkewnessScore: 1, // score will stay at the deafault 100%
			expectedError:         false,
		},
		{
			name:                       "Unsorted Slice",
			intervalsBetweenTimestamps: []float64{7.7, 6.6, 4.4, 1.1, 5.5, 3.3, 2.2},
			expectedSkewness:           0,
			expectedSkewnessScore:      1,
			expectedError:              false,
		},
		{
			name:                       "Empty",
			intervalsBetweenTimestamps: []float64{},
			expectedSkewness:           0,
			expectedSkewnessScore:      0,
			expectedError:              true,
		},
		{
			name:                       "Less than 3 elements", // can't calculate skewness with fewer than 3 elements
			intervalsBetweenTimestamps: []float64{1, 2},
			expectedSkewness:           0,
			expectedSkewnessScore:      0,
			expectedError:              true,
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			skew, score, err := calculateBowleySkewness(test.intervalsBetweenTimestamps)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated values
			require.InDelta(test.expectedSkewness, skew, 0.001, "Expected skewness to be %v, got %v", test.expectedSkewness, skew)
			require.InDelta(test.expectedSkewnessScore, score, 0.001, "Expected score to be %v, got %v", test.expectedSkewnessScore, score)
		})
	}
}

func TestCalculateDistinctCounts(t *testing.T) {
	tests := []struct {
		name             string
		sortedInput      []float64
		expectedDistinct []int64
		expectedCounts   []int64
		expectedMode     int64
		expectedMaxCount int64
		expectError      bool
	}{
		{
			name:             "Simple List",
			sortedInput:      []float64{1, 2, 2, 3, 3, 3, 4, 5, 5},
			expectedDistinct: []int64{1, 2, 3, 4, 5},
			expectedCounts:   []int64{1, 2, 3, 1, 2},
			expectedMode:     3,
			expectedMaxCount: 3,
			expectError:      false,
		},
		{
			name:             "Simple List 2",
			sortedInput:      []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedDistinct: []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedCounts:   []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedMode:     1,
			expectedMaxCount: 1,
			expectError:      false,
		},
		{
			name:             "Timestamp Slice",
			sortedInput:      []float64{1517338924, 1517338924, 1517338924, 1609459200, 1609459200, 1612137600, 1612137600},
			expectedDistinct: []int64{1517338924, 1609459200, 1612137600},
			expectedCounts:   []int64{3, 2, 2},
			expectedMode:     1517338924,
			expectedMaxCount: 3,
			expectError:      false,
		},
		{
			name:             "Unsorted Slice",
			sortedInput:      []float64{3.3, 2.2, 4.4, 1.1, 5.5, 3.3, 2.2},
			expectedDistinct: []int64{1, 2, 3, 4, 5},
			expectedCounts:   []int64{1, 2, 2, 1, 1},
			expectedMode:     2,
			expectedMaxCount: 2,
			expectError:      false,
		},
		{
			name:             "Empty Slice",
			sortedInput:      []float64{},
			expectedDistinct: nil,
			expectedCounts:   nil,
			expectedMode:     0,
			expectedMaxCount: 0,
			expectError:      true,
		},
		{
			name:             "Slice with Only One Element",
			sortedInput:      []float64{1},
			expectedDistinct: nil,
			expectedCounts:   nil,
			expectedMode:     0,
			expectedMaxCount: 0,
			expectError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			distinctNumbers, countsArray, mode, maxCount, err := calculateDistinctCounts(test.sortedInput)

			// check if an error was expected
			require.Equal(test.expectError, err != nil, "Expected error to be %v, got %v", test.expectError, err)

			// check the calculated values
			require.Equal(test.expectedDistinct, distinctNumbers, "Expected distinctNumbers to be %v, got %v", test.expectedDistinct, distinctNumbers)
			require.Equal(test.expectedCounts, countsArray, "Expected countsArray to be %v, got %v", test.expectedCounts, countsArray)
			require.Equal(test.expectedMode, mode, "Expected mode to be %v, got %v", test.expectedMode, mode)
			require.Equal(test.expectedMaxCount, maxCount, "Expected maxCount to be %v, got %v", test.expectedMaxCount, maxCount)
		})
	}
}

func TestCalculateMedianAbsoluteDeviation(t *testing.T) {
	tests := []struct {
		name          string
		inputData     []float64
		defaultScore  float64
		expectedMAD   float64
		expectedScore float64
		expectError   bool
	}{
		{
			name:          "Simple List",
			inputData:     []float64{1, 2, 2, 3, 3, 3, 4, 5, 5},
			defaultScore:  1,
			expectedMAD:   1,
			expectedScore: 0.6667,
			expectError:   false,
		},
		{
			name:          "Simple List 2",
			inputData:     []float64{11, 12, 12, 14, 15, 16},
			defaultScore:  1,
			expectedMAD:   1.5,
			expectedScore: 0.8846,
			expectError:   false,
		},
		{
			name:          "Bigger Numbers",
			inputData:     []float64{1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500},
			defaultScore:  1,
			expectedMAD:   1250,
			expectedScore: 0.6154,
			expectError:   false,
		},
		{
			name:          "Unsorted Slice",
			inputData:     []float64{4000, 2500, 2000, 1500, 5500, 3500, 1000, 4500, 5000, 3000},
			defaultScore:  1,
			expectedMAD:   1250,
			expectedScore: 0.6154,
			expectError:   false,
		},
		{
			name:          "Empty Slice",
			inputData:     []float64{},
			defaultScore:  1,
			expectedMAD:   0,
			expectedScore: 0,
			expectError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			mad, score, err := calculateMedianAbsoluteDeviation(test.inputData, test.defaultScore)

			// check if an error was expected
			require.Equal(test.expectError, err != nil, "error should match expected value")

			// check the calculated MAD
			require.InDelta(test.expectedMAD, mad, 0.001, "Expected MAD to be %v, got %v", test.expectedMAD, mad)

			// check the calculated score
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)
		})
	}
}

func TestComputeHistogramBins(t *testing.T) {
	tests := []struct {
		name             string
		startTime        int64
		endTime          int64
		numBins          int
		expectedBinEdges []float64
		expectedError    bool
	}{
		{
			name:             "Simple List",
			startTime:        0,
			endTime:          10,
			numBins:          2,
			expectedBinEdges: []float64{0, 5, 10},
			expectedError:    false,
		},
		{
			name:             "Total Bins Less Than Time Range",
			startTime:        0,
			endTime:          100,
			numBins:          5,
			expectedBinEdges: []float64{0, 20, 40, 60, 80, 100},
			expectedError:    false,
		},
		{
			name:      "Total Bins Equal to Time Range",
			startTime: 0,
			endTime:   24,
			numBins:   24,
			// total edges: 24 + 1 = 25
			// step: (maxTS - minTS) / total edges - 1 = 24 / 24 = 1
			// first edge: 1, last edge: 24
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			// expectedBinEdges: []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
			expectedBinEdges: []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
			expectedError:    false,
		},
		{
			name:      "Total Bins Exceed Time Range",
			startTime: 0,
			endTime:   10,
			numBins:   24,
			// total edges: 10 + 1 = 11
			// step: (maxTS - minTS) / numBins - 1 = 10 / 24 = 0.4167
			// first edge: 0, last edge: 10
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			expectedBinEdges: []float64{0, 0.4167, 0.8333, 1.25, 1.6667, 2.0833, 2.5, 2.9167, 3.3333, 3.75, 4.1667, 4.5833, 5, 5.4167, 5.8333, 6.25, 6.6667, 7.0833, 7.5, 7.9167, 8.3333, 8.75, 9.1667, 9.5833, 10},
			expectedError:    false,
		},

		{
			name:      "Timestamp List",
			startTime: 1517336042,
			endTime:   1517422440,
			numBins:   24,
			// total edges: 24 + 1 = 25
			// step: (maxTS - minTS) / total edges - 1 = 1517422440 - 1517336042 / 24 = 86398 / 24 = 3599.9167
			// first edge: 1517336042, last edge: 1517422440
			// bin edges: first edge, first edge + step, first edge + 2*step, ... , last edge
			expectedBinEdges: []float64{
				1517336042,
				1517336042 + 3599.9167,
				1517336042 + 2*3599.9167,
				1517336042 + 3*3599.9167,
				1517336042 + 4*3599.9167,
				1517336042 + 5*3599.9167,
				1517336042 + 6*3599.9167,
				1517336042 + 7*3599.9167,
				1517336042 + 8*3599.9167,
				1517336042 + 9*3599.9167,
				1517336042 + 10*3599.9167,
				1517336042 + 11*3599.9167,
				1517336042 + 12*3599.9167,
				1517336042 + 13*3599.9167,
				1517336042 + 14*3599.9167,
				1517336042 + 15*3599.9167,
				1517336042 + 16*3599.9167,
				1517336042 + 17*3599.9167,
				1517336042 + 18*3599.9167,
				1517336042 + 19*3599.9167,
				1517336042 + 20*3599.9167,
				1517336042 + 21*3599.9167,
				1517336042 + 22*3599.9167,
				1517336042 + 23*3599.9167,
				1517422440,
			},
			expectedError: false,
		},
		{
			name:          "Invalid Number of Bins",
			startTime:     0,
			endTime:       100,
			numBins:       0,
			expectedError: true,
		},
		{
			name:          "Invalid Time Range - End Time < Start Time",
			startTime:     10,
			endTime:       5,
			numBins:       5,
			expectedError: true,
		},
		{
			name:             "Invalid Time Range - End Time == Start Time",
			startTime:        0,
			endTime:          0,
			numBins:          5,
			expectedBinEdges: nil,
			expectedError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			divs, err := computeHistogramBins(test.startTime, test.endTime, test.numBins)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", false, err)

			// check the calculated values
			// require.Equal(test.expectedBinEdges, divs, "Expected bin edges to be %v, got %v", test.expectedBinEdges, divs)
			require.InDeltaSlice(test.expectedBinEdges, divs, 0.01, "Expected bin edges to be %v, got %v", test.expectedBinEdges, divs)
		})
	}
}

func TestCalculateCoefficientOfVariationScore(t *testing.T) {
	tests := []struct {
		name          string
		freqList      []int
		total         int
		expectedScore float64
		expectedError bool
	}{
		{
			name:          "Uniform Distribution",
			freqList:      []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expectedScore: 1,
			expectedError: false,
		},
		{
			name:     "Normal Distribution",
			freqList: []int{950, 970, 990, 1010, 1030, 1050, 1070},
			total:    7150,
			// sd = 40, mean = 1010, CV = 0.0396
			expectedScore: 0.96, // score = round((1-0.0396)*1000) = 960, 960/1000 = 0.96
			expectedError: false,
		},
		{
			name:     "CV less than 1",
			freqList: []int{1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009},
			// CV = 0.0028594
			expectedScore: 0.9971406, // score = 1-0.0028594 = 0.9971406
			expectedError: false,
		},
		{
			name:          "CV greater than 1",
			freqList:      []int{1, 5, 10, 50, 100, 500, 1000, 5000, 10000},
			expectedScore: 0.0, // score should be 0 for CV > 1
			expectedError: false,
		},
		{
			name:          "Empty List",
			freqList:      []int{},
			expectedScore: 0,
			expectedError: true,
		},
		{
			name:          "Negative Slice Values",
			freqList:      []int{-5, -10, -7, -3, -8},
			expectedScore: 0,
			expectedError: true,
		},
		{
			name:          "Total is zero",
			freqList:      []int{0, 0, 0, 0, 0},
			expectedScore: 0,
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			score, err := calculateCoefficientOfVariationScore(test.freqList)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)

			// check the calculated values
			require.InDelta(test.expectedScore, score, 0.001, "Expected score to be %v, got %v", test.expectedScore, score)
		})
	}
}

func TestCalculateBimodalFitScore(t *testing.T) {

	tests := []struct {
		name                       string
		freqCount                  map[int32]int32
		totalBars                  int
		modalOutlierRemoval        int
		minHoursForBimodalAnalysis int
		expectedScore              float64
		expectedError              bool
	}{
		{
			name: "Perfect Single Modal",
			freqCount: map[int32]int32{
				1: 10,
			},
			totalBars:                  10,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			expectedScore:              1,
			expectedError:              false,
		},
		{
			name: "Imperfect Single Modal",
			freqCount: map[int32]int32{
				1: 50,
				2: 5,
			},
			totalBars:                  60,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			// (50+5)/max(60-1, 1) = 55/59 = 0.932
			expectedScore: 0.932,
			expectedError: false,
		},
		{
			name: "Perfect Single Modal with Outlier Removal",
			freqCount: map[int32]int32{
				1: 10,
				2: 1,
			},
			totalBars:                  11,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			expectedScore:              1,
			expectedError:              false,
		},
		{
			name: "Imperfect Single Modal with Outlier Removal",
			freqCount: map[int32]int32{
				1: 50,
				2: 1,
				3: 1,
			},
			totalBars:                  56,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			// (50+1/56-1) = 51/55 = 0.927
			expectedScore: 0.927,
			expectedError: false,
		},
		{
			name: "Perfect Bimodal",
			freqCount: map[int32]int32{
				1: 10,
				2: 10,
			},
			totalBars:                  20,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			expectedScore:              1,
			expectedError:              false,
		},
		{
			name: "Imperfect Bimodal",
			freqCount: map[int32]int32{
				1: 50,
				2: 30,
				3: 1,
				4: 2,
			},
			totalBars:                  83,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			// (50+30)/(83-1) = 80/82 = 0.976
			expectedScore: 0.976,
			expectedError: false,
		},
		{
			name: "Perfect Bimodal with Outlier Removal",
			freqCount: map[int32]int32{
				1: 10,
				2: 10,
				3: 1,
			},
			totalBars:                  21,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			expectedScore:              1,
			expectedError:              false,
		},
		{
			name: "Imperfect Bimodal with Outlier Removal",
			freqCount: map[int32]int32{
				1: 50,
				2: 30,
				3: 1,
				4: 2,
				5: 1,
			},
			totalBars:                  84,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 10,
			// (50+30)/(84-1) = 80/83 = 0.964
			expectedScore: 0.964,
			expectedError: false,
		},
		{
			name: "Number of Bars < Minimum Hours For Bimodal Analysis",
			freqCount: map[int32]int32{
				1: 2,
				2: 3,
			},
			totalBars:                  5,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 11,
			expectedScore:              0.0,
			expectedError:              false,
		},
		{
			// this should not happen in practice, as this value will get vetted when the config is loaded
			name: "Minimum Hours For Bimodal Analysis < 3",
			freqCount: map[int32]int32{
				1: 1,
				2: 1,
			},
			totalBars:                  2,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 2,
			expectedScore:              0.0, // score would be 100% if the setting was not overridden
			expectedError:              false,
		},
		{
			name:                       "Number of Bars <= 0",
			freqCount:                  map[int32]int32{1: 2, 2: 3},
			totalBars:                  0,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 11,
			expectedScore:              0.0,
			expectedError:              true,
		},
		{
			name:                       "Empty Frequency Count",
			freqCount:                  map[int32]int32{},
			totalBars:                  20,
			modalOutlierRemoval:        1,
			minHoursForBimodalAnalysis: 11,
			expectedScore:              0.0,
			expectedError:              true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			score, err := calculateBimodalFitScore(tc.freqCount, tc.totalBars, tc.modalOutlierRemoval, tc.minHoursForBimodalAnalysis)

			// check if an error was expected
			require.Equal(tc.expectedError, err != nil, "Expected error to be %v, got %v", tc.expectedError, err)

			// check the calculated values
			require.InDelta(tc.expectedScore, score, 0.001, "score should match expected value")
		})
	}

}

func TestCreateHistogram(t *testing.T) {

	tests := []struct {
		name               string
		binEdges           []float64
		tsList             []uint32
		modalSensitivity   float64
		expectedHistogram  []int
		expectedFreqCount  map[int32]int32
		expectedTotalBars  int
		expectedLongestRun int
		expectedError      bool
		errorContains      string
	}{
		{
			name:               "Simple Flat Histogram",
			binEdges:           []float64{0, 10, 20, 30},
			tsList:             []uint32{1, 5, 11, 15, 21, 25},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{2, 2, 2},
			expectedFreqCount:  map[int32]int32{2: 3},
			expectedTotalBars:  3,
			expectedLongestRun: 3,
			expectedError:      false,
		},
		{
			name:               "Multiple Bins, but All Timestamps in One",
			binEdges:           []float64{0, 100, 200},
			tsList:             []uint32{10, 20, 30, 40},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{4, 0},
			expectedFreqCount:  map[int32]int32{4: 1},
			expectedTotalBars:  1,
			expectedLongestRun: 1,
			expectedError:      false,
		},
		{
			name:               "Single Bin",
			binEdges:           []float64{0, 100},
			tsList:             []uint32{10, 20, 30, 40, 50},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{5},
			expectedFreqCount:  map[int32]int32{5: 1},
			expectedTotalBars:  1,
			expectedLongestRun: 1,
			expectedError:      false,
		},
		{
			name:               "Histogram with Gaps and Wraparound Timestamp Run",
			binEdges:           []float64{0, 50, 100, 150, 200, 250},
			tsList:             []uint32{10, 20, 100, 110, 110, 220},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{2, 0, 3, 0, 1},
			expectedFreqCount:  map[int32]int32{1: 1, 2: 1, 3: 1},
			expectedTotalBars:  3,
			expectedLongestRun: 2,
			expectedError:      false,
		},
		{
			name:               "Bimodal Histogram",
			binEdges:           []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			tsList:             []uint32{1, 2, 3, 4, 15, 21, 22, 23, 24, 35, 41, 42, 43, 44, 55, 61, 62, 63, 64, 75, 81, 82, 83, 84, 95},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{4, 1, 4, 1, 4, 1, 4, 1, 4, 1},
			expectedFreqCount:  map[int32]int32{1: 5, 4: 5},
			expectedTotalBars:  10,
			expectedLongestRun: 10,
			expectedError:      false,
		},
		{
			name:               "Last Value in Value List Equal to Last Bin Edge",
			tsList:             []uint32{98, 99, 99, 100, 100, 100, 101, 101, 102},
			modalSensitivity:   0.05,
			binEdges:           []float64{98, 98.5, 99, 99.5, 100, 100.5, 101, 101.5, 102},
			expectedHistogram:  []int{1, 0, 2, 0, 3, 0, 2, 1},
			expectedFreqCount:  map[int32]int32{1: 2, 2: 2, 3: 1},
			expectedTotalBars:  5,
			expectedLongestRun: 3,
			expectedError:      false,
		},
		{
			name:     "High Modal Sensitivity",
			binEdges: []float64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000},
			tsList: []uint32{
				10, 15, 20, 25, 30, 35, 40, 45, 50,
				110, 115, 120, 125, 130, 135, 140, 145, 150, 155,
				210, 215, 220, 225, 230, 235, 240, 245, 250, 255, 260,
				300, 305, 330, 335, 337, 339, 343, 349, 380, 399,
				400, 404, 424, 434, 437, 439, 443, 449, 480, 495, 499,
				510, 515, 520, 525, 530, 535, 540, 545, 550,
				610, 615, 620, 625, 630, 635, 640, 645, 650, 655,
				710, 715, 720, 725, 730, 735, 740, 745, 750, 755, 760,
				810, 815, 820, 825, 830, 835, 840, 845, 850, 855,
				900, 910, 920, 930, 940, 960, 970, 980, 990,
			},
			modalSensitivity:   0.2,
			expectedHistogram:  []int{9, 10, 11, 10, 11, 9, 10, 11, 10, 9},
			expectedFreqCount:  map[int32]int32{9: 10},
			expectedTotalBars:  10,
			expectedLongestRun: 10,
			expectedError:      false,
		},
		{
			name:     "Low Modal Sensitivity",
			binEdges: []float64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000},
			tsList: []uint32{
				10, 15, 20, 25, 30, 35, 40, 45, 50,
				110, 115, 120, 125, 130, 135, 140, 145, 150, 155,
				210, 215, 220, 225, 230, 235, 240, 245, 250, 255, 260,
				300, 305, 330, 335, 337, 339, 343, 349, 380, 399,
				400, 404, 424, 434, 437, 439, 443, 449, 480, 495, 499,
				510, 515, 520, 525, 530, 535, 540, 545, 550,
				610, 615, 620, 625, 630, 635, 640, 645, 650, 655,
				710, 715, 720, 725, 730, 735, 740, 745, 750, 755, 760,
				810, 815, 820, 825, 830, 835, 840, 845, 850, 855,
				900, 910, 920, 930, 940, 960, 970, 980, 990,
			},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{9, 10, 11, 10, 11, 9, 10, 11, 10, 9},
			expectedFreqCount:  map[int32]int32{9: 3, 10: 4, 11: 3},
			expectedTotalBars:  10,
			expectedLongestRun: 10,
			expectedError:      false,
		},
		{
			name:     "Bimodal - High Sensitivity",
			binEdges: []float64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000},
			tsList: []uint32{
				10, 15, 20, 25, 30, 35, 40, 45, 50,
				110, 115, 120, 125, 130, 135, 140, 145, 150, 155,
				210, 215, 220, 225, 230, 235, 240, 245, 250, 255, 260,
				300, 305, 330, 335, 337, 339, 343, 349, 380, 399,
				400, 404, 424, 434, 437, 439, 443, 449, 480, 495, 499,
				510, 515, 520, 525, 530, 535, 540, 545, 550,
				610, 615, 620, 625, 630, 635, 640, 645, 650, 655,
				710, 715, 720, 725, 730, 735, 740, 745, 750, 755, 760,
				810, 815, 820, 825, 830, 835, 840, 845, 850, 855,
				900, 910, 920, 930, 940, 960, 970, 980, 990,
				1010, 1011, 1055,
				1110, 1155,
				1210, 1260, 1270,
				1300, 1330,
				1404, 1440, 1445,
				1550, 1560,
				1600, 1650, 1660,
				1770, 1780,
				1880, 1890, 1899,
				1999, 2000,
			},
			modalSensitivity:   0.3,
			expectedHistogram:  []int{9, 10, 11, 10, 11, 9, 10, 11, 10, 9, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2},
			expectedFreqCount:  map[int32]int32{0: 10, 8: 10},
			expectedTotalBars:  20,
			expectedLongestRun: 20,
		},
		{
			name:     "Bimodal - Low Sensitivity",
			binEdges: []float64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000},
			tsList: []uint32{
				10, 15, 20, 25, 30, 35, 40, 45, 50,
				110, 115, 120, 125, 130, 135, 140, 145, 150, 155,
				210, 215, 220, 225, 230, 235, 240, 245, 250, 255, 260,
				300, 305, 330, 335, 337, 339, 343, 349, 380, 399,
				400, 404, 424, 434, 437, 439, 443, 449, 480, 495, 499,
				510, 515, 520, 525, 530, 535, 540, 545, 550,
				610, 615, 620, 625, 630, 635, 640, 645, 650, 655,
				710, 715, 720, 725, 730, 735, 740, 745, 750, 755, 760,
				810, 815, 820, 825, 830, 835, 840, 845, 850, 855,
				900, 910, 920, 930, 940, 960, 970, 980, 990,
				1010, 1011, 1055,
				1110, 1155,
				1210, 1260, 1270,
				1300, 1330,
				1404, 1440, 1445,
				1550, 1560,
				1600, 1650, 1660,
				1770, 1780,
				1880, 1890, 1899,
				1999, 2000,
			},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{9, 10, 11, 10, 11, 9, 10, 11, 10, 9, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2},
			expectedFreqCount:  map[int32]int32{9: 3, 10: 4, 11: 3, 2: 5, 3: 5},
			expectedTotalBars:  20,
			expectedLongestRun: 20,
		},
		{
			name:               "Unsorted Slice",
			binEdges:           []float64{0, 100, 200, 300, 400, 500},
			tsList:             []uint32{450, 10, 30, 205, 299},
			modalSensitivity:   0.05,
			expectedHistogram:  []int{2, 0, 2, 0, 1},
			expectedFreqCount:  map[int32]int32{1: 1, 2: 2},
			expectedTotalBars:  3,
			expectedLongestRun: 2,
			expectedError:      false,
		},
		{
			name:               "Invalid Bin Edges",
			binEdges:           []float64{10},
			tsList:             []uint32{15, 22, 35},
			modalSensitivity:   0.05,
			expectedHistogram:  []int(nil),
			expectedFreqCount:  map[int32]int32(nil),
			expectedTotalBars:  0,
			expectedLongestRun: 0,
			expectedError:      true,
			errorContains:      "binEdges must contain at least 2 elements",
		},
		{
			name:               "Empty Timestamps Slice",
			binEdges:           []float64{10, 20, 30, 40},
			tsList:             []uint32{},
			modalSensitivity:   0.05,
			expectedHistogram:  []int(nil),
			expectedFreqCount:  map[int32]int32(nil),
			expectedTotalBars:  0,
			expectedLongestRun: 0,
			expectedError:      true,
			errorContains:      "timestamp slice must not be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			frequencies, freqCount, totalBars, longestRun, err := createHistogram(test.binEdges, test.tsList, test.modalSensitivity)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, err)
			// if test.errorContains != "" {
			// 	require.Contains(err.Error(), test.errorContains)
			// }

			// check the calculated values
			require.Equal(test.expectedHistogram, frequencies, "Expected frequencies to be %v, got %v", test.expectedHistogram, frequencies)
			require.Equal(test.expectedFreqCount, freqCount, "Expected freqCount to be %v, got %v", test.expectedFreqCount, freqCount)
			require.Equal(test.expectedTotalBars, totalBars, "Expected totalBars to be %v, got %v", test.expectedTotalBars, totalBars)
			require.Equal(test.expectedLongestRun, longestRun, "Expected longestRun to be %v, got %v", test.expectedLongestRun, longestRun)

		})
	}
}

func TestGetFrequencyCounts(t *testing.T) {
	tests := []struct {
		name               string
		histogram          []int
		bimodalSensitivity float64
		expectedCounts     map[int32]int32
		totalBars          int
		longestRun         int
		expectedError      bool
	}{
		{
			name:               "Simple Flat Histogram",
			histogram:          []int{2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			bimodalSensitivity: 0.05,
			expectedCounts:     map[int32]int32{2: 10},
			totalBars:          10,
			longestRun:         10,
			expectedError:      false,
		},
		{
			name:               "Simple Bimodal Histogram",
			histogram:          []int{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
			bimodalSensitivity: 0.05,
			expectedCounts:     map[int32]int32{2: 10, 4: 10},
			totalBars:          20,
			longestRun:         20,
			expectedError:      false,
		},
		{
			name:               "Flat Histogram with Gaps",
			histogram:          []int{2, 0, 2, 0, 2, 0, 2, 0, 2, 0},
			bimodalSensitivity: 0.05,
			expectedCounts:     map[int32]int32{2: 5},
			totalBars:          5,
			longestRun:         1,
			expectedError:      false,
		},
		{
			name:               "Bimodal Histogram with Gaps",
			histogram:          []int{2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4, 0},
			bimodalSensitivity: 0.05,
			expectedCounts:     map[int32]int32{2: 5, 4: 4},
			totalBars:          9,
			longestRun:         5,
			expectedError:      false,
		},
		// histogram:          []int{9999, 9950, 10000, 10042, 10001, 9960},
		{
			name:               "Flat Histogram with Closely-Valued Bars",
			histogram:          []int{900, 901, 899, 900, 899, 902, 900, 901},
			bimodalSensitivity: 0.05,
			// bin size = ceiling(largestnum * 0.05) = 902 * 0.05 = 45.1 = 46
			// first bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 900/46 = 19.5652 = 19 * 46 = 874
			// all values within 46 of 874 will be grouped together
			expectedCounts: map[int32]int32{874: 8},
			totalBars:      8,
			longestRun:     8,
			expectedError:  false,
		},
		{
			name:               "Bimodal Histogram with Closely-Valued Bars",
			histogram:          []int{100, 105, 100, 300, 305, 300},
			bimodalSensitivity: 0.1,
			// bin size = ceiling(largestnum * 0.1) = 305 * 0.1 = 30.5 = 31
			// first bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 100/31 = 3.2258 = 3 * 31 = 93
			// second bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 300/31 = 9.6774 = 9 * 31 = 279
			expectedCounts: map[int32]int32{93: 3, 279: 3},
			totalBars:      6,
			longestRun:     6,
			expectedError:  false,
		},
		{
			name:               "Multimodal Histogram",
			histogram:          []int{100, 105, 100, 300, 305, 300, 500, 505, 500, 700, 705, 700},
			bimodalSensitivity: 0.1,
			// bin size = ceiling(largestnum * 0.1) = 705 * 0.1 = 70.5 = 71
			// first bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 100/71 = 1.4085 = 1 * 71 = 71
			// second bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 300/71 = 4.2254 = 4 * 71 = 284
			// third bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 500/71 = 7.0423 = 7 * 71 = 497
			// fourth bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 700/71 = 9.8592 = 9 * 71 = 639
			expectedCounts: map[int32]int32{71: 3, 284: 3, 497: 3, 639: 3},
			totalBars:      12,
			longestRun:     12,
			expectedError:  false,
		},
		{
			name:               "High Sensitivity - Fine Grained",
			histogram:          []int{100, 100, 101, 101, 102, 200, 200, 201, 201, 202, 300, 300, 301, 301, 302},
			bimodalSensitivity: 0.001, // High sensitivity to minor variations
			expectedCounts:     map[int32]int32{100: 2, 101: 2, 102: 1, 200: 2, 201: 2, 202: 1, 300: 2, 301: 2, 302: 1},
			totalBars:          15,
			longestRun:         15, // Maximum consecutive run is 2
		},
		{
			name:               "Low Sensitivity - Coarse Grained",
			histogram:          []int{100, 100, 101, 101, 102, 200, 200, 201, 201, 202, 300, 300, 301, 301, 302},
			bimodalSensitivity: 0.1, // Lower sensitivity, more forgiving to variations
			// bin size = ceiling(largestnum * 0.1) = 302 * 0.1 = 30.2 = 31
			// first bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 100/31 = 3.2258 = 3 * 31 = 93
			// second bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 200/31 = 6.4516 = 6 * 31 = 186
			// third bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 300/31 = 9.6774 = 9 * 31 = 279
			expectedCounts: map[int32]int32{93: 5, 186: 5, 279: 5},
			totalBars:      15,
			longestRun:     15,
		},
		{
			name:               "Wraparound Longest Run with Gap",
			histogram:          []int{2002, 2000, 1999, 2005, 1990, 0, 0, 0, 0, 0, 0, 2000, 2001, 2002, 2003, 2004},
			bimodalSensitivity: 0.05,
			// bin size = ceiling(largestnum * 0.05) = 2005 * 0.05 = 100.25 = 101
			// first bin:
			// math.Floor(float64(frequency)/binSize) * binSize = 2000/101 = 19.8019 = 19 * 101 = 1919
			expectedCounts: map[int32]int32{1919: 10},
			totalBars:      10,
			longestRun:     10,
			expectedError:  false,
		},
		{
			name:               "Empty Histogram",
			histogram:          []int{},
			bimodalSensitivity: 0.05,
			expectedCounts:     nil,
			totalBars:          0,
			longestRun:         0,
			expectedError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			// run the function
			freqCounts, totalBars, longestRun, err := getFrequencyCounts(test.histogram, test.bimodalSensitivity)

			// check if an error was expected
			require.Equal(test.expectedError, err != nil, "Expected error to be %v, got %v", test.expectedError, false)

			// check the calculated values
			require.Equal(test.expectedCounts, freqCounts, "Expected freqCounts to be %v, got %v", test.expectedCounts, freqCounts)
			require.Equal(test.totalBars, totalBars, "Expected totalBars to be %v, got %v", test.totalBars, totalBars)
			require.Equal(test.longestRun, longestRun, "Expected longestRun to be %v, got %v", test.longestRun, longestRun)

		})
	}
}
