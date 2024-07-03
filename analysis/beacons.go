package analysis

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/activecm/rita/logger"
	"github.com/activecm/rita/util"

	"github.com/montanaflynn/stats"
)

var ErrInvalidDatasetTimeRange = errors.New("invalid dataset timerange: min ts is greater than or equal to max ts")
var ErrInputSliceEmpty = errors.New("input slice must not be empty")

type Beacon struct {
	BeaconType     string  `ch:"beacon_type"` // (sni, ip)
	Score          float32 `ch:"beacon_score"`
	TimestampScore float32 `ch:"ts_score"`
	DataSizeScore  float32 `ch:"ds_score"`
	HistogramScore float32 `ch:"hist_score"`
	DurationScore  float32 `ch:"dur_score"`

	TSIntervals      []int64 `ch:"ts_intervals"`
	TSIntervalCounts []int64 `ch:"ts_interval_counts"`
	DSSizes          []int64 `ch:"ds_sizes"`
	DSCounts         []int64 `ch:"ds_size_counts"`
}

func (analyzer *Analyzer) analyzeBeacon(entry *AnalysisResult) (Beacon, error) {
	logger := logger.GetLogger()
	var beacon Beacon

	// verify that minTSBeacon < maxTSBeacon
	if analyzer.minTSBeacon.After(analyzer.maxTSBeacon) || analyzer.minTSBeacon.Equal(analyzer.maxTSBeacon) {
		logger.Err(ErrInvalidDatasetTimeRange).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, ErrInvalidDatasetTimeRange
	}

	// calculate timestamp scores and metrics (unused fields are used by the test functions)
	tsScore, _, _, intervals, intervalCounts, _, _, err := getTimestampScore(entry.TSList)
	if err != nil {
		logger.Err(err).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, err
	}

	// calculate data size scores and metrics
	dsScore, _, _, dsSizes, dsCounts, _, _, err := getDataSizeScore(entry.BytesList)
	if err != nil {
		logger.Err(err).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, err
	}

	// calculate histogram score (note: we currently look at a 24 hour period)
	_, _, totalBars, longestRun, histScore, err := getHistogramScore(analyzer.minTSBeacon.Unix(), analyzer.maxTSBeacon.Unix(), entry.TSList, analyzer.Config.Scoring.Beacon.HistModeSensitivity, analyzer.Config.Scoring.Beacon.HistBimodalOutlierRemoval, analyzer.Config.Scoring.Beacon.HistBimodalMinHours, 24)
	if err != nil {
		logger.Err(err).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, err
	}

	// calculate duration score
	_, _, durScore, err := getDurationScore(analyzer.minTSBeacon.Unix(), analyzer.maxTSBeacon.Unix(), int64(entry.TSList[0]), int64(entry.TSList[len(entry.TSList)-1]), totalBars, longestRun, analyzer.Config.Scoring.Beacon.DurMinHours, analyzer.Config.Scoring.Beacon.DurIdealNumberOfConsistentHours)
	if err != nil {
		logger.Err(err).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, err
	}

	// calculate overall beacon score
	score, err := getBeaconScore(tsScore, analyzer.Config.Scoring.Beacon.TsWeight,
		dsScore, analyzer.Config.Scoring.Beacon.DsWeight,
		durScore, analyzer.Config.Scoring.Beacon.DurWeight,
		histScore, analyzer.Config.Scoring.Beacon.HistWeight)
	if err != nil {
		logger.Err(err).Caller().Str("src", entry.Src.String()).Str("dst", entry.Dst.String()).Str("fqdn", entry.FQDN).Send()
		return beacon, err
	}

	// create beacon
	// float64 values are cast to float32 for more efficient storage in the database, as the values
	// are not expected to exceed the range of a float32. The cast is done here at the end of analysis
	// since most of the go math functions require or return float64
	beacon = Beacon{
		// score fields
		BeaconType:     entry.BeaconType,
		Score:          float32(score),
		TimestampScore: float32(tsScore),
		DataSizeScore:  float32(dsScore),
		HistogramScore: float32(histScore),
		DurationScore:  float32(durScore),

		// graphing fields
		TSIntervals:      intervals,
		TSIntervalCounts: intervalCounts,
		DSSizes:          dsSizes,
		DSCounts:         dsCounts,
	}
	return beacon, nil
}

// getBeaconScore calculates the overall beacon score from the weighted subscores
func getBeaconScore(tsScore, tsWeight, dsScore, dsWeight, durScore, durWeight, histScore, histWeight float64) (float64, error) {
	// ensure that the calculated subscores are between 0 and 1
	scores := []float64{tsScore, dsScore, durScore, histScore}
	for _, score := range scores {
		if score < 0 || score > 1 {
			return 0, errors.New("scores must be between 0 and 1")
		}
	}

	// ensure that the weights are between 0 and 1 and sum to 1
	weights := []float64{tsWeight, dsWeight, durWeight, histWeight}
	weightSum := 0.0
	for _, weight := range weights {
		if weight < 0 || weight > 1 {
			return 0, errors.New("weights must be between 0 and 1")
		}
		weightSum += weight
	}
	if weightSum != 1 {
		return 0, errors.New("weights must sum to 1")
	}

	// calculate the final score
	score := math.Round(((tsScore*tsWeight)+(dsScore*dsWeight)+(durScore*durWeight)+(histScore*histWeight))*1000) / 1000

	return score, nil
}

func getTimestampScore(tsList []uint32) (float64, float64, float64, []int64, []int64, int64, int64, error) {
	// ensure that the input slice has at least 4 elements (need at least 3 intervals, which requires at least 4 timestamps)
	if len(tsList) < 4 {
		return 0, 0, 0, nil, nil, 0, 0, fmt.Errorf("timestamp slice must contain at least 4 elements")
	}

	// find the delta times between the full, non-unique timestamp list and sort
	// this will be used for the user/ graph reference variables returned by createCountMap
	// the slice size is tsLength - 1 since we are looking at the deltas between timestamps
	deltaTimesFull := make([]float64, len(tsList)-1)
	nonZeroCounter := 0
	for i := 0; i < len(tsList)-1; i++ {
		interval := tsList[i+1] - tsList[i]
		if interval > 0 {
			nonZeroCounter++
		}
		deltaTimesFull[i] = float64(interval)
	}

	// ensure that there are at least 3 non-zero intervals
	if nonZeroCounter < 3 {
		return 0, 0, 0, nil, nil, 0, 0, fmt.Errorf("timestamp slice must contain at least 3 non-zero intervals")
	}

	// sort the delta times
	slices.Sort(deltaTimesFull)

	// get a list of the intervals found in the data, the number of times the interval was found, and the most occurring interval
	intervals, intervalCounts, tsMode, tsModeCount, err := calculateDistinctCounts(deltaTimesFull)
	if err != nil {
		return 0, 0, 0, nil, nil, 0, 0, err
	}

	// deltas from the unique timestamp list are used for the scoring calculations. These can be
	// calculated by taking the slice of the sorted deltaTimesFull from the first non-zero index
	nonZeroIndex := 0

	for i := 0; i < len(deltaTimesFull); i++ {
		if deltaTimesFull[i] > 0 {
			nonZeroIndex = i
			break
		}
	}
	deltaTimes := deltaTimesFull[nonZeroIndex:]

	// calculate ts score, skew, and median absolute deviation
	tsScore, tsSkew, tsMadm, err := calculateStatisticalScore(deltaTimes, 1)
	if err != nil {
		return 0, 0, 0, nil, nil, 0, 0, err
	}

	return tsScore, tsSkew, tsMadm, intervals, intervalCounts, tsMode, tsModeCount, nil

}

func getDataSizeScore(bytesList []float64) (float64, float64, float64, []int64, []int64, int64, int64, error) {
	// ensure that the input slice has at least 3 elements
	if len(bytesList) < 3 {
		return 0, 0, 0, nil, nil, 0, 0, fmt.Errorf("bytes slice must contain at least 3 elements")
	}

	// sort the data sizes
	slices.Sort(bytesList)

	// find distinct data sizes and their counts
	dsSizes, dsCounts, dsMode, dsModeCount, err := calculateDistinctCounts(bytesList)
	if err != nil {
		return 0, 0, 0, nil, nil, 0, 0, err
	}

	// calculate datasize score, skew, and median absolute deviation
	dsScore, dsSkew, dsMadm, err := calculateStatisticalScore(bytesList, 0)
	if err != nil {
		return 0, 0, 0, nil, nil, 0, 0, err
	}

	return dsScore, dsSkew, dsMadm, dsSizes, dsCounts, dsMode, dsModeCount, nil

}

// calculateStatisticalScore calculates the statistical score, skew, and median absolute derivation for a given list of float64 values
func calculateStatisticalScore(values []float64, defaultMadScore float64) (float64, float64, float64, error) {
	// ensure that the input slice is not empty
	if len(values) == 0 {
		return 0, 0, 0, ErrInputSliceEmpty
	}

	// calculate the skewness of the values
	skew, skewScore, err := calculateBowleySkewness(values)
	if err != nil {
		return 0, 0, 0, err
	}

	// calculate the median absolute deviation of the values
	mad, madScore, err := calculateMedianAbsoluteDeviation(values, defaultMadScore)
	if err != nil {
		return 0, 0, 0, err
	}

	// calculate final statistical score
	score := math.Round(((skewScore+madScore)/2.0)*1000) / 1000

	return score, skew, mad, nil
}

// getHistogramScore calculates a score based on the histogram of timestamps of a host pair over a specified period of time
func getHistogramScore(datasetMin int64, datasetMax int64, tsList []uint32, modeSensitivity float64, bimodalOutlierRemoval int, bimodalMinHoursSeen int, beaconTimeSpan int) ([]int, map[int32]int32, int, int, float64, error) {
	// ensure that the input slice is not empty
	if len(tsList) == 0 {
		return nil, nil, 0, 0, 0, ErrInputSliceEmpty
	}

	// ensure that the dataset time range is valid
	if datasetMax <= datasetMin {
		return nil, nil, 0, 0, 0, ErrInvalidDatasetTimeRange
	}

	// get histogram bin eges (note: we currently look at a 24 hour period)
	binEdges, err := computeHistogramBins(datasetMin, datasetMax, beaconTimeSpan)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	// use timestamps to get freqencies for each bin
	freqList, freqCount, totalBars, longestRun, err := createHistogram(binEdges, tsList, modeSensitivity)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	// calculate first potential score: coefficient of variation
	// coefficient of variation will help score histograms that have jitter in the number of
	// connections but where the overall graph would still look relatively flat and consistent
	// calculate coefficient of variation score
	cvScore, err := calculateCoefficientOfVariationScore(freqList)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	// calculate second potential score: bimodal fit
	// this will score well for graphs that have 2-3 flat sections in their connection histogram,
	// or a bimodal freqCount histogram.
	bimodalFitScore, err := calculateBimodalFitScore(freqCount, totalBars, bimodalOutlierRemoval, bimodalMinHoursSeen)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	// calculate final score
	// the final score is the max of the coefficient of variation and bimodal fit scores
	score := math.Max(cvScore, bimodalFitScore)

	return freqList, freqCount, totalBars, longestRun, score, nil
}

// getDurationScore calculates a duration score based on the provided input parameters, provided that
// a sufficient amount of hours (default threshold: 6 hours) are represented in the connection frequency histogram.
// The duration score is derived from two potential subscores: dataset timespan coverage and consistency of connection hours
func getDurationScore(datasetMin int64, datasetMax int64, histMin int64, histMax int64, totalBars int, longestConsecutiveRun int, minHoursThreshold int, idealNumberConsistentHours int) (float64, float64, float64, error) {

	// ensure that the input values are valid
	if minHoursThreshold < 1 || idealNumberConsistentHours < 1 || datasetMax <= datasetMin || histMax <= histMin {
		return 0, 0, 0, fmt.Errorf("invalid input for getDurationScore: check parameter values")
	}

	// initialize the variables to hold the coverage, consistency, and final score
	coverage, consistency, score := float64(0), float64(0), float64(0)

	// check if there is enough data to calculate the duration score
	if totalBars >= minHoursThreshold {

		// calculate the dataset timespan coverage score
		// this score reflects the proportion of time covered by the dataset in relation to the
		// entire specified timeframe. It is calculated as:
		//    [ timestamp of last connection - timestamp of first connection ] /
		//    [ last timestamp of dataset - first timestamp of dataset ]
		coverage = math.Ceil((float64(histMax-histMin)/float64(datasetMax-datasetMin))*1000) / 1000
		if coverage > 1.0 {
			coverage = 1.0
		}

		// calculate the consistency score
		// this score measures the continuity of connection hours, considering the longest run
		// of consecutive hours observed. Consecutive hours include wrap-around from the start
		// to the end of the dataset. It is calculated as:
		//    [ longest run of consecutive hours seen] / [ Ideal consecutive hours (default: 12) ]
		consistency = math.Ceil((float64(longestConsecutiveRun)/float64(idealNumberConsistentHours))*1000) / 1000
		if consistency > 1.0 {
			consistency = 1.0
		}

		// take the maximum of the two scores
		score = math.Max(coverage, consistency)
	}

	return coverage, consistency, score, nil
}

// calculateBowleySkewness calculates a measure of skewness for a distribution.
// Perfect beacons would have symmetric delta time and size distributions
func calculateBowleySkewness(data []float64) (float64, float64, error) {
	// ensure that the input slice is not empty, since the minimum number of
	// elements required to calculate skewness is 3
	if len(data) < 3 {
		return 0, 0, fmt.Errorf("input slice must not contain fewer than 3 elements")
	}

	// calculate the quartiles
	quartiles, err := stats.Quartile(data)

	// returns an error if array was empty or quartiles could not be calculated
	if err != nil {
		return 0, 0, err
	}

	// calculate the numerator
	num := quartiles.Q1 + quartiles.Q3 - 2*quartiles.Q2

	// calculate the denominator
	den := quartiles.Q3 - quartiles.Q1

	// set the skewness to zero
	skewness := float64(0)

	// Bowley Skewness = (Q3+Q1 – 2Q2) / (Q3 – Q1)
	// if the denominator less than 10 or the median is equal to the lower or upper quartile, the skewness is zero
	if den >= 10 && quartiles.Q2 != quartiles.Q1 && quartiles.Q2 != quartiles.Q3 {
		skewness = float64(num) / float64(den)
	}

	// calculate score
	score := 1.0 - math.Abs(skewness)

	// return the skewness and the score
	return skewness, score, nil
}

// calculateMedianAbsoluteDeviation calculates the Median Absolute Deviation (MAD) about the median,
// providing a score that measures the dispersion of a distribution. Perfectly consistent data would
// result in a MAD score close to zero
func calculateMedianAbsoluteDeviation(data []float64, defaultScore float64) (float64, float64, error) {
	// ensure the the input slice is not empty
	if len(data) == 0 {
		return 0, 0, ErrInputSliceEmpty
	}

	// ensure that the input is sorted
	if !sort.Float64sAreSorted(data) {
		sort.Float64s(data)
	}

	// calculate the median of the input data
	median, err := stats.Median(data)
	if err != nil {
		return 0, 0, err
	}

	mad, err := stats.MedianAbsoluteDeviation(data)
	if err != nil {
		return 0, 0, err
	}

	// calculate the MAD score, which is a measure of how much the data deviates from its median.
	// The MAD is normalized by dividing it by the median. The resulting score represents how
	// consistent the data is. As the MAD increases, the score decreases, indicating more dispersion
	score := defaultScore
	if median >= 1 {
		score = (median - mad) / median
	}

	// If the score is less than zero or NaN, return zero
	if score < 0 || math.IsNaN(score) {
		score = 0
	}

	// Return the MAD and the normalized MAD score
	return mad, score, nil
}

// calculateDistinctCounts takes a sorted slice of numbers as input and returns
// distinct numbers, their counts, mode, and maximum count
func calculateDistinctCounts(input []float64) ([]int64, []int64, int64, int64, error) {
	// ensure that the input slice has at least 2 elements
	if len(input) < 2 {
		return nil, nil, 0, 0, fmt.Errorf("input slice must have at least two elements")
	}

	// ensure that the input is sorted
	if !sort.Float64sAreSorted(input) {
		sort.Float64s(input)
	}

	// create a slice to store unique elements from the number list,
	// starting with an empty slice (length 0) and a capacity based on
	// the assumption that every element in input is distinct
	distinctNumbers := make([]int64, 0, len(input))

	// countsMap will map each distinct number to its count
	countsMap := make(map[int64]int64)

	// initialize with the first element of input
	lastNumber := int64(input[0])
	distinctNumbers = append(distinctNumbers, lastNumber)
	countsMap[lastNumber]++

	// iterate through input to identify unique elements and count occurrences
	for _, currentNumber := range input[1:] {
		current := int64(currentNumber)

		// if the current number is different from the last one, add it to distinctNumbers
		if lastNumber != current {
			distinctNumbers = append(distinctNumbers, current)
		}

		// increment the count for the current number
		countsMap[current]++
		lastNumber = current
	}

	// prepare the results by calculating countsArray, mode, and maxCount
	countsArray := make([]int64, len(distinctNumbers))
	mode := distinctNumbers[0]  // assume the mode is the first distinct number
	maxCount := countsMap[mode] // initialize maxCount with the count of the assumed mode

	// find the mode and maximum count
	for i, number := range distinctNumbers {
		count := countsMap[number]
		countsArray[i] = count

		// update mode and maxCount if a higher count is found
		if count > maxCount {
			maxCount = count
			mode = number
		}
	}

	return distinctNumbers, countsArray, mode, maxCount, nil
}

// computeHistogramBins creates evenly spaced bins for the histogram based on the given timestamp range
// and the desired number of bins
func computeHistogramBins(startTime int64, endTime int64, numBins int) ([]float64, error) {
	// ensure that the number of bins is positive
	if numBins <= 0 {
		return nil, errors.New("number of desired histogram bins must be greater than 0")
	}

	// ensure that time range is valid
	if endTime <= startTime {
		return nil, errors.New("invalid histogram time range")
	}

	// set number of bin eges. Since the edges include the endpoints,
	// the number of edges will be one more than the number of desired bins
	edgeCount := numBins + 1

	// calculate the step size for evenly spaced bins between startTime and endTime
	step := float64(endTime-startTime) / float64(numBins)

	// create slice to store the bin edges
	binEdges := make([]float64, edgeCount)

	// explicitly set the first bin edge to startTime
	binEdges[0] = float64(startTime)

	// create evenly spaced bin edges between startTime and endTime
	for i := 1; i < edgeCount-1; i++ {
		binEdges[i] = float64(startTime) + (float64(i) * step)
	}

	// explicitly set the last edge to endTime
	binEdges[edgeCount-1] = float64(endTime)

	return binEdges, nil
}

// createHistogram calculates the distribution of timestamps across given bin edges
// func createHistogram(binEdges []uint32, timestamps []uint32, modeSensitivity float64) ([]int, map[int32]int32, int, int, error) {
func createHistogram(binEdges []float64, timestamps []uint32, modeSensitivity float64) ([]int, map[int32]int32, int, int, error) {
	// validate input
	if len(binEdges) < 2 {
		return nil, nil, 0, 0, errors.New("bin edges must contain at least 2 elements")
	}

	if len(timestamps) == 0 {
		return nil, nil, 0, 0, ErrInputSliceEmpty
	}

	// ensure that the bin edges are sorted
	if !sort.Float64sAreSorted(binEdges) {
		sort.Float64s(binEdges)
	}

	// ensure that the timestamps are sorted
	if !util.UInt32sAreSorted(timestamps) {
		util.SortUInt32s(timestamps)
	}

	// Initialize nextBinIndex with the second bin edge to start comparisons.
	// This variable represents the upper limit of the current bin, used to determine
	// if a timestamp falls within the current bin or if we need to move to the next bin.
	currentBinIndex := 0
	nextBinEdge := binEdges[currentBinIndex+1]

	// calculate the number of connections that occurred within the time span represented by each bin
	// this is basically a histogram of the number of connections that occurred within each bin
	// i,e, for a timestamp list of [1, 5, 23, 25, 42, 45] and bin edges [0, 10, 20, 30, 40, 50],
	// the histogram would be [2,0,2,0,2]
	connectionHistogram := make([]int, len(binEdges)-1)

	// loop over sorted timestamp list
	for _, timestamp := range timestamps {

		// increment if still in the current bin
		if float64(timestamp) < nextBinEdge {
			connectionHistogram[currentBinIndex]++
			continue
		}

		// if the timestamp is greater than or equal to the next bin edge, move to the next bin
		for j := currentBinIndex + 1; j < len(binEdges)-1; j++ {
			currentBinIndex = j
			nextBinEdge = binEdges[j+1]
			if float64(timestamp) < binEdges[j+1] {
				break
			}

		}

		// increment count
		// this will also capture and increment for a situation where the final timestamp is
		// equal to the final bin
		connectionHistogram[currentBinIndex]++
	}

	// get histogram frequency counts
	freqCount, totalBars, longestRun, err := getFrequencyCounts(connectionHistogram, modeSensitivity)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	return connectionHistogram, freqCount, totalBars, longestRun, nil

}

// getFrequencyCounts calculates the frequency counts for a connection histogram, essentially counting how many
// bars of a certain height are present in the histogram. The function also calculates the longest consecutive run
// of hours seen in the connection frequency histogram, including wrap around from start to end of dataset.

// alt description:
// calculateFrequencyCounts analyzes the histogram to calculate the frequency of each count,
// the total number of non-empty bins, and the longest consecutive sequence of non-empty bins seen in the histogram,
// including wrap around from start to end of dataset
func getFrequencyCounts(connectionHistogram []int, modeSensitivity float64) (map[int32]int32, int, int, error) {
	// ensure that the input is not empty
	if len(connectionHistogram) == 0 {
		return nil, 0, 0, ErrInputSliceEmpty
	}

	// count total non-zero histogram entries (total bars) and find the largest histogram entry
	totalBars := 0
	largestConnCount := 0
	for _, entry := range connectionHistogram {
		if entry > 0 {
			totalBars++
		}
		if entry > largestConnCount {
			largestConnCount = entry
		}

	}

	// create a map to store the frequency counts for the connection histogram
	freqCount := make(map[int32]int32)

	// determine bin size for frequency histogram. This is expressed as a percentage of the
	// largest connection count and controls how forgiving the bimodal analysis is to variation.
	// This keeps us from putting multiple bars of very similar height into different bins and
	// interpreting them as separate modes. For example, if the largest connection count is 1000 and
	// the bimodal sensitivity is 0.05, the bin size will be 50. This means that any bars with a
	// within 50 of each other will be grouped together. This is useful for handling small variations
	// in connection counts that are not significant enough to be considered separate modes.
	// the percentage is set in the rita yaml file (default: 0.05)
	binSize := math.Ceil(float64(largestConnCount) * modeSensitivity)

	// make variables to track the longest consecutive run of hours seen in the connection
	// frequency histogram, including wrap around from start to end of dataset
	longestRun := 0
	currentRun := 0

	// make frequency count map
	for i := 0; i < len(connectionHistogram)*2; i++ {

		// get the bar from the connection histogram, wrapping around if necessary
		frequency := connectionHistogram[i%len(connectionHistogram)]

		// track the longest run of consecutive bars seen in the connection frequency histogram
		if frequency > 0 {
			currentRun++

		} else {

			if currentRun > longestRun {
				longestRun = currentRun
			}
			currentRun = 0

		}

		// limit calculation to the first loop through the connection histogram
		if i < len(connectionHistogram) {

			// if the bar is greater than zero, parse it into the map entry that matches its frequency
			if frequency > 0 {

				// figure out which bin to parse the frequency bar into
				bin := int(math.Floor(float64(frequency)/binSize) * binSize)

				// create or increment bin
				if _, ok := freqCount[int32(bin)]; !ok {
					freqCount[int32(bin)] = 1
				} else {
					freqCount[int32(bin)]++
				}
			}

		}

	}

	if currentRun > longestRun {
		longestRun = currentRun
	}

	// since we could end up with 2*freqListLen for the longest run if
	// every hour has a connection, we will fix it up here.
	if longestRun > len(connectionHistogram) {
		longestRun = len(connectionHistogram)
	}

	return freqCount, totalBars, longestRun, nil
}

// calculateCoefficientOfVariationScore calculates the coefficient of variation score for a connection histogram.
// The score is used to evaluate the level of jitter in the number of connections, providing a measure of how flat
// or consistent the overall graph appears. A high coefficient of variation implies more jitter, resulting in a lower score.
// The final score is normalized between 0 and 1, where 1 indicates perfect consistency, and 0 indicates high variation.
//
// potential alt description:
// calculateCoefficientOfVariationScore calculates a score based on the coefficient of variation (CV) for a given frequency list.
// The CV is a standardized measure of dispersion of a frequency distribution, defined as the ratio of the standard deviation to the mean.
// This function returns a score inversely related to the CV, aiming to score datasets based on their uniformity or consistency.
func calculateCoefficientOfVariationScore(freqList []int) (float64, error) {
	// ensure that the input is valid

	// ensure that the input slice is not empty
	if len(freqList) == 0 {
		return 0, ErrInputSliceEmpty
	}

	// calculate the total and check for negative values. This will also ensure that the
	// mean cannot be zero, a case for which the CV is unreliable
	total := 0
	for _, entry := range freqList {
		if entry < 0 {
			return 0, errors.New("input slice must not contain negative values")
		}
		total += entry
	}
	if total <= 0 {
		return 0, errors.New("total must be greater than zero")
	}

	// calculate mean
	freqMean := float64(total) / float64(len(freqList))

	// calculate standard deviation
	sd := float64(0)
	for j := 0; j < len(freqList); j++ {
		sd += math.Pow(float64(freqList[j])-freqMean, 2)
	}
	sd = math.Sqrt(sd / float64(len(freqList)))

	// calculate coefficient of variation
	cv := sd / math.Abs(freqMean)

	// ensures datasets with high variability are not given negative scores
	var cvScore float64
	if cv > 1.0 {
		cvScore = 0.0
	} else {
		cvScore = math.Round((1.0-cv)*1000) / 1000
	}

	// ensure that the score does not exceed 1
	if cvScore > 1.0 {
		cvScore = 1.0
	}

	return cvScore, nil
}

// calculateBimodalFitScore calculates the bimodal fit score for a connection histogram.
// This score is particularly useful for graphs that exhibit 2-3 flat sections in their connection histogram or a
// bimodal frequency count histogram. It is designed to handle scenarios like a beacon alternating between low and high
// connection counts per hour. The score is computed only if the number of total bars on the histogram is at least the
// specified minimum (default: 11). The final score is normalized between 0 and 1, where 1 indicates a perfect fit for
// bimodal patterns, and 0 indicates a poor fit.
func calculateBimodalFitScore(freqCount map[int32]int32, totalBars int, modalOutlierRemoval int, minHoursForBimodalAnalysis int) (float64, error) {
	// ensure that the input is valid
	if len(freqCount) == 0 {
		return 0, errors.New("frequency count map must not be empty")
	}

	// ensure that totalBars is greater than zero
	if totalBars <= 0 {
		return 0, errors.New("total bars must be greater than zero")
	}

	// override the minimum hours seen back to default (just under half a day) if it is less than 6 (a quarter of a day)
	// this is to ensure that the bimodal fit score is not calculated for histograms with too few bars, as in that case
	// a histogram with 1-2 bars will always be given a high bimoal fit score as it technically has 1-2 modes. This is also
	// vetted when the config is loaded and should in theory not happen outside of tests
	if minHoursForBimodalAnalysis < 6 {
		minHoursForBimodalAnalysis = 11
	}

	// initialize bimodal fit to zero
	modalFit := float64(0)

	// check if the histogram has enough non-zero bars to analyze for bimodal patterns
	if totalBars >= minHoursForBimodalAnalysis {

		largest, secondLargest := int32(0), int32(0)

		// get the top two frequency mode bars in the histogram
		for _, value := range freqCount {
			if value > largest {
				secondLargest = largest
				largest = value
			} else if value > secondLargest {
				secondLargest = value
			}
		}

		// calculate the percentage of hour blocks that fit into the top two mode bins.
		// a small buffer for the score is provided by throwing out a yaml-set number of
		// potential outlier bins (default: 1)
		adjustedTotalBars := math.Max(float64(totalBars-modalOutlierRemoval), 1) // ensure that the denominator is not zero
		modalFit = float64(largest+secondLargest) / adjustedTotalBars
	}

	// calculate final score, ensuring that it does not exceed 1
	modalFitScore := math.Round(float64(modalFit)*1000) / 1000
	if modalFitScore > 1.0 {
		modalFitScore = 1.0
	}

	return modalFitScore, nil
}
