package viewer_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/viewer"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func (s *ViewerTestSuite) TestSearchBar() {
	t := s.T()

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(t, err)

	require.False(t, m.SearchBar.TextInput.Focused(), "search bar should not be focused without focusing it first")

	// / key switches focus to the searchbar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type:  tea.KeyRunes,
			Runes: []rune{47},
		},
	))

	require.True(t, m.SearchBar.TextInput.Focused(), "search bar should be focused after focusing it")

	// enter key unfocuses the searchbar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyEnter,
		},
	))

	time.Sleep(time.Second)
	require.False(t, m.SearchBar.TextInput.Focused(), "search bar should not be focused after pressing enter")

	// refocus the searchbar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type:  tea.KeyRunes,
			Runes: []rune{47},
		},
	))

	require.True(t, m.SearchBar.TextInput.Focused(), "search bar should be focused after focusing it, #2")

	// esc key unfocuses the searchbar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyEsc,
		},
	))

	require.False(t, m.SearchBar.TextInput.Focused(), "search bar should not be focused after pressing esc")

}

// TestSearchFilters tests the parsing and setting of the Filter object
// this test is not part of the
func TestSearchFilters(t *testing.T) {

	type testCase struct {
		name      string
		search    string
		shouldErr bool
		filter    *viewer.Filter
	}
	cases := []testCase{
		// threat category
		{name: "Filter by critical severity", search: "severity:critical", filter: &viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: ">", Value: fmt.Sprint(config.HIGH_CATEGORY_SCORE)}}}},
		{name: "Filter by high severity", search: "severity:high", filter: &viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<=", Value: fmt.Sprint(config.HIGH_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.MEDIUM_CATEGORY_SCORE)}}}},
		{name: "Filter by medium severity", search: "severity:medium", filter: &viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<", Value: fmt.Sprint(config.MEDIUM_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.LOW_CATEGORY_SCORE)}}}},
		{name: "Filter by low severity", search: "severity:low", filter: &viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<", Value: fmt.Sprint(config.LOW_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.NONE_CATEGORY_SCORE)}}}},
		// generic invalid entries
		{name: "Filter by wrong severity", search: "severity:none", shouldErr: true},
		{name: "Filter with no value after colon", search: "severity:", shouldErr: true},
		{name: "Invalid filtering column", search: "nugget:10.55.100.100", shouldErr: true},
		{name: "Invalid characters: comma", search: "src:10.55.100.100, dst:20.5.4.3", shouldErr: true},
		{name: "Invalid characters: equals", search: "src=10.55.100.100 dst=20.5.4.3", shouldErr: true},
		// ip
		{name: "Filter by src IP", search: "src:10.55.100.100", filter: &viewer.Filter{Src: "10.55.100.100"}},
		{name: "Filter by src IPv6", search: "src:2001:0000:3238:DFE1:0063:0000:0000:FEFB", filter: &viewer.Filter{Src: "2001:0000:3238:DFE1:0063:0000:0000:FEFB"}},
		{name: "Filter by invalid src IP", search: "src:1000.5.03", shouldErr: true},
		{name: "Filter by FQDN in src IP field (invalid)", search: "src:www.alexa.com", shouldErr: true},

		{name: "Filter by dst IP", search: "dst:165.227.88.15", filter: &viewer.Filter{Dst: "165.227.88.15"}},
		{name: "Filter by dst IPv6", search: "dst:2001:0000:3238:DFE1:0063:0000:0000:FEFB", filter: &viewer.Filter{Dst: "2001:0000:3238:DFE1:0063:0000:0000:FEFB"}},
		{name: "Filter by invalid dst IP", search: "dst:1000.5.03", shouldErr: true},
		{name: "Filter by FQDN", search: "dst:www.alexa.com", filter: &viewer.Filter{Fqdn: "www.alexa.com"}},
		{name: "Filter by invalid FQDN", search: "dst:ww?w.alex??a.com", shouldErr: true},
		// beacon score
		{name: "Filter by beacon score, equals", search: "beacon:90", filter: &viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "=", Value: "0.90"}}},
		{name: "Filter by beacon score, greater than", search: "beacon:>50", filter: &viewer.Filter{Beacon: viewer.OperatorFilter{Operator: ">", Value: "0.50"}}},
		{name: "Filter by beacon score, greater than or equal", search: "beacon:>=60", filter: &viewer.Filter{Beacon: viewer.OperatorFilter{Operator: ">=", Value: "0.60"}}},
		{name: "Filter by beacon score, less than", search: "beacon:<70", filter: &viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "<", Value: "0.70"}}},
		{name: "Filter by beacon score, less than or equal", search: "beacon:<=34", filter: &viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "<=", Value: "0.34"}}},
		{name: "Filter by beacon score greater than 100", search: "beacon:800", shouldErr: true},
		{name: "Filter by beacon score, equal sign", search: "beacon:=80", shouldErr: true},
		{name: "Filter by beacon score, percent sign", search: "beacon:80%", shouldErr: true},
		{name: "Filter by beacon score, float", search: "beacon:0.8", shouldErr: true},
		// duration
		{name: "Filter by duration, equals", search: "duration:1.5h", filter: &viewer.Filter{Duration: viewer.OperatorFilter{Operator: "=", Value: "5400"}}},
		{name: "Filter by duration, greater than", search: "duration:>2h45m", filter: &viewer.Filter{Duration: viewer.OperatorFilter{Operator: ">", Value: "9900"}}},
		{name: "Filter by duration, greater than or equal", search: "duration:>=10s", filter: &viewer.Filter{Duration: viewer.OperatorFilter{Operator: ">=", Value: "10"}}},
		{name: "Filter by duration, less than", search: "duration:<20m", filter: &viewer.Filter{Duration: viewer.OperatorFilter{Operator: "<", Value: "1200"}}},
		{name: "Filter by duration, less than or equal", search: "duration:<=30h", filter: &viewer.Filter{Duration: viewer.OperatorFilter{Operator: "<=", Value: "108000"}}},
		{name: "Filter by duration, equal sign", search: "duration:=80m", shouldErr: true},
		{name: "Filter by duration, days", search: "duration:5d", shouldErr: true},
		{name: "Filter by duration, years", search: "duration:1y", shouldErr: true},
		{name: "Filter by duration, no time unit", search: "duration:1000", shouldErr: true},
		// subdomains
		{name: "Filter by subdomains, equals", search: "subdomains:1000", filter: &viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "=", Value: "1000"}}},
		{name: "Filter by subdomains, greater than", search: "subdomains:>234", filter: &viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: ">", Value: "234"}}},
		{name: "Filter by subdomains, greater than or equal", search: "subdomains:>=112", filter: &viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: ">=", Value: "112"}}},
		{name: "Filter by subdomains, less than", search: "subdomains:<12", filter: &viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "<", Value: "12"}}},
		{name: "Filter by subdomains, less than or equal", search: "subdomains:<=64", filter: &viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "<=", Value: "64"}}},
		{name: "Filter by subdomains, equal sign", search: "subdomains:=98", shouldErr: true},
		{name: "Filter by subdomains, float", search: "subdomains:1.6", shouldErr: true},
		// threat intel
		{name: "Filter by threat intel, true", search: "threat_intel:true", filter: &viewer.Filter{ThreatIntel: "true"}},
		{name: "Filter by threat intel, false", search: "threat_intel:false", filter: &viewer.Filter{ThreatIntel: "false"}},
		{name: "Filter by threat intel, numerical value, true", search: "threat_intel:1", filter: &viewer.Filter{ThreatIntel: "true"}},
		{name: "Filter by threat intel, numerical value, false", search: "threat_intel:0", filter: &viewer.Filter{ThreatIntel: "false"}},
		{name: "Filter by threat intel, invalid value", search: "threat_intel:ture", shouldErr: true},
		// invalid sort criteria
		{name: "Sort by invalid column, ascending", search: "sort:nugget-asc", shouldErr: true},
		{name: "Sort by invalid column, descending", search: "sort:nugget-desc", shouldErr: true},
		{name: "Sort by invalid column, no direction", search: "sort:nugget", shouldErr: true},
		// sort beacon
		{name: "Sort by beacon score, ascending", search: "sort:beacon-asc", filter: &viewer.Filter{SortBeacon: "asc"}},
		{name: "Sort by beacon score, descending", search: "sort:beacon-desc", filter: &viewer.Filter{SortBeacon: "desc"}},
		{name: "Sort by beacon score, no direction", search: "sort:beacon", shouldErr: true},
		// sort duration
		{name: "Sort by duration, ascending", search: "sort:duration-asc", filter: &viewer.Filter{SortDuration: "asc"}},
		{name: "Sort by duration, descending", search: "sort:duration-desc", filter: &viewer.Filter{SortDuration: "desc"}},
		{name: "Sort by duration, no direction", search: "sort:duration", shouldErr: true},
		// sort severity
		{name: "Sort by severity, ascending", search: "sort:severity-asc", filter: &viewer.Filter{SortSeverity: "asc"}},
		{name: "Sort by severity, descending", search: "sort:severity-desc", filter: &viewer.Filter{SortSeverity: "desc"}},
		{name: "Sort by severity, no direction", search: "sort:severity", shouldErr: true},
		// criteria combinations
		{name: "Search by src IP, sort by beacon", search: "src:10.55.100.100 sort:beacon-desc", filter: &viewer.Filter{Src: "10.55.100.100", SortBeacon: "desc"}},
		{name: "Search by src IP, sort by beacon, !No Space!", search: "src:10.55.100.100sort:beacon-desc", shouldErr: true},
		{name: "Search by src IP, sort by beacon, incomplete dst IP", search: "src:10.55.100.100 sort:beacon-desc dst:196.8", shouldErr: true},
		{name: "Search by src IP, sort by beacon, trailing space", search: "src:10.55.100.100 sort:beacon-desc ", filter: &viewer.Filter{Src: "10.55.100.100", SortBeacon: "desc"}},
		{name: "Search by src IP, sort by beacon, leading space", search: " src:10.55.100.100 sort:beacon-desc", filter: &viewer.Filter{Src: "10.55.100.100", SortBeacon: "desc"}},
		{name: "Search by src IP, dst IP", search: " src:10.55.100.100 dst:165.227.88.15", filter: &viewer.Filter{Src: "10.55.100.100", Dst: "165.227.88.15"}},
		{name: "Search by src IP, dst IP, sort by severity", search: " src:10.55.100.100 dst:165.227.88.15 sort:severity-asc", filter: &viewer.Filter{Src: "10.55.100.100", Dst: "165.227.88.15", SortSeverity: "asc"}},
	}

	for _, test := range cases {
		filter, err := viewer.ParseSearchInput(test.search)
		require.Equal(t, test.shouldErr, err != "", "Test '%s' error status doesn't match expected status, got %t, expected %t", test.name, err != "", test.shouldErr)
		require.Equal(t, test.filter, filter, "Test '%s' filter doesn't match expected value, got %v, expected %v", test.name, filter, test.filter)
	}

}

func (s *ViewerTestSuite) TestSearchResults() {
	t := s.T()

	type testCase struct {
		name         string
		filter       viewer.Filter
		valid        func(*viewer.Item) bool
		sorted       func(float64, *viewer.Item) (float64, bool) // return whether or not the next item follows the right sort order
		field        func(*viewer.Item) float64                  // returns the field of the column being sorted
		checkSorting bool
	}

	cases := []testCase{
		{name: "Filter by src IP", filter: viewer.Filter{Src: "10.55.100.100"}, valid: func(i *viewer.Item) bool { return i.Src.String() == "10.55.100.100" }},
		{name: "Filter by dst IP", filter: viewer.Filter{Dst: "165.227.88.15"}, valid: func(i *viewer.Item) bool { return i.Dst.String() == "165.227.88.15" }},
		{name: "Filter by FQDN", filter: viewer.Filter{Fqdn: "www.alexa.com"}, valid: func(i *viewer.Item) bool { return i.FQDN == "www.alexa.com" }},
		// beacon
		{name: "Filter by beacon score", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "=", Value: "1"}}, valid: func(i *viewer.Item) bool { return i.BeaconScore == 1 }},
		{name: "Filter by beacon score, greater than", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: ">", Value: "0.98"}, SortBeacon: "asc"}, valid: func(i *viewer.Item) bool { return i.BeaconScore > 0.98 }},
		{name: "Filter by beacon score, greater than or equal", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: ">=", Value: "0.98"}}, valid: func(i *viewer.Item) bool { return i.BeaconScore >= 0.98 }},
		{name: "Filter by beacon score, greater than or equal", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: ">=", Value: "0.98"}}, valid: func(i *viewer.Item) bool { return i.BeaconScore >= 0.98 }},
		{name: "Filter by beacon score, less than", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "<", Value: "0.70"}}, valid: func(i *viewer.Item) bool { return i.BeaconScore < 0.7 }},
		{name: "Filter by beacon score, less than or equal", filter: viewer.Filter{Beacon: viewer.OperatorFilter{Operator: "<=", Value: "0.70"}}, valid: func(i *viewer.Item) bool { return i.BeaconScore <= 0.7 }},
		// duration
		{name: "Filter by duration", filter: viewer.Filter{Duration: viewer.OperatorFilter{Operator: "=", Value: "2584"}}, valid: func(i *viewer.Item) bool { return math.Floor(i.TotalDuration) == 2584 }},
		{name: "Filter by duration, greater than", filter: viewer.Filter{Duration: viewer.OperatorFilter{Operator: ">", Value: "21600"}}, valid: func(i *viewer.Item) bool { return i.TotalDuration > 21600 }},
		{name: "Filter by duration, greater than or equal", filter: viewer.Filter{Duration: viewer.OperatorFilter{Operator: ">=", Value: "21600"}}, valid: func(i *viewer.Item) bool { return i.TotalDuration >= 21600 }},
		{name: "Filter by duration, less than", filter: viewer.Filter{Duration: viewer.OperatorFilter{Operator: "<", Value: "3600"}}, valid: func(i *viewer.Item) bool { return i.TotalDuration < 3600 }},
		{name: "Filter by duration, less than or equal", filter: viewer.Filter{Duration: viewer.OperatorFilter{Operator: "<=", Value: "3600"}}, valid: func(i *viewer.Item) bool { return i.TotalDuration <= 3600 }},
		// subdomains
		{name: "Filter by subdomains", filter: viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "=", Value: "62468"}}, valid: func(i *viewer.Item) bool { return i.Subdomains == 62468 }},
		{name: "Filter by subdomains, greater than", filter: viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: ">", Value: "50"}}, valid: func(i *viewer.Item) bool { return i.Subdomains > 50 }},
		{name: "Filter by subdomains, greater than or equal", filter: viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: ">=", Value: "50"}}, valid: func(i *viewer.Item) bool { return i.Subdomains >= 50 }},
		{name: "Filter by subdomains, less than", filter: viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "<", Value: "100"}}, valid: func(i *viewer.Item) bool { return i.Subdomains < 100 }},
		{name: "Filter by subdomains, less than or equal", filter: viewer.Filter{Subdomains: viewer.OperatorFilter{Operator: "<=", Value: "100"}}, valid: func(i *viewer.Item) bool { return i.Subdomains <= 100 }},
		// threat intel
		// {name: "Filter by threat intel, true", filter: viewer.Filter{ThreatIntel: "true"}, valid: func(i *viewer.Item) bool { return i.ThreatIntelScore > 0 }},
		{name: "Filter by threat intel, false", filter: viewer.Filter{ThreatIntel: "false"}, valid: func(i *viewer.Item) bool { return i.ThreatIntelScore == 0 }},
		// severity
		{name: "Filter by severity, critical", filter: viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: ">", Value: fmt.Sprint(config.HIGH_CATEGORY_SCORE)}}}, valid: func(i *viewer.Item) bool { return i.FinalScore > config.HIGH_CATEGORY_SCORE }},
		{name: "Filter by severity, high", filter: viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<=", Value: fmt.Sprint(config.HIGH_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.MEDIUM_CATEGORY_SCORE)}}}, valid: func(i *viewer.Item) bool {
			return i.FinalScore <= config.HIGH_CATEGORY_SCORE && i.FinalScore >= config.MEDIUM_CATEGORY_SCORE
		}},
		{name: "Filter by severity, medium", filter: viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<", Value: fmt.Sprint(config.MEDIUM_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.LOW_CATEGORY_SCORE)}}}, valid: func(i *viewer.Item) bool {
			return i.FinalScore < config.MEDIUM_CATEGORY_SCORE && i.FinalScore >= config.LOW_CATEGORY_SCORE
		}},
		{name: "Filter by severity, low", filter: viewer.Filter{Severity: []viewer.OperatorFilter{{Operator: "<", Value: fmt.Sprint(config.LOW_CATEGORY_SCORE)}, {Operator: ">=", Value: fmt.Sprint(config.NONE_CATEGORY_SCORE)}}}, valid: func(i *viewer.Item) bool {
			return i.FinalScore < config.LOW_CATEGORY_SCORE && i.FinalScore >= config.NONE_CATEGORY_SCORE
		}},
		// sorting
		{name: "Sort by beacon, desc", filter: viewer.Filter{SortBeacon: "desc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.BeaconScore }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.BeaconScore, newItem.BeaconScore <= currentVal
		}},
		{name: "Sort by beacon, asc", filter: viewer.Filter{SortBeacon: "asc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.BeaconScore }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.BeaconScore, newItem.BeaconScore >= currentVal
		}},
		{name: "Sort by duration, desc", filter: viewer.Filter{SortDuration: "desc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.TotalDuration }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.TotalDuration, newItem.TotalDuration <= currentVal
		}},
		{name: "Sort by duration, asc", filter: viewer.Filter{SortDuration: "asc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.TotalDuration }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.TotalDuration, newItem.TotalDuration >= currentVal
		}},
		{name: "Sort by severity, desc", filter: viewer.Filter{SortSeverity: "desc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.FinalScore }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.FinalScore, newItem.FinalScore <= currentVal
		}},
		{name: "Sort by severity, asc", filter: viewer.Filter{SortSeverity: "asc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return item.FinalScore }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return newItem.FinalScore, newItem.FinalScore >= currentVal
		}},
		{name: "Sort by subdomains, desc", filter: viewer.Filter{SortSubdomains: "desc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return float64(item.Subdomains) }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return float64(newItem.Subdomains), float64(newItem.Subdomains) <= currentVal
		}},
		{name: "Sort by subdomains, asc", filter: viewer.Filter{SortSubdomains: "asc"}, checkSorting: true, field: func(item *viewer.Item) float64 { return float64(item.Subdomains) }, sorted: func(currentVal float64, newItem *viewer.Item) (float64, bool) {
			return float64(newItem.Subdomains), float64(newItem.Subdomains) >= currentVal
		}},
	}
	for i := 0; i < len(cases); i++ {
		test := cases[i]
		s.Run(test.name, func() {
			// get filter from search bar
			res, appliedFilter, err := viewer.GetResults(s.db, &test.filter, 0, 20, s.minTimestamp)
			require.NoError(t, err)
			require.True(t, appliedFilter, "filter criteria must be applied")
			require.NotEmpty(t, res, "results should not be empty")
			// check the sorting order if this test is for checking sorting
			if test.checkSorting {
				sorted := validateSorting(res, test.field, test.sorted)
				require.True(t, sorted, "results should be sorted correctly")
			} else {
				// check that the results match the search criteria
				valid := true
				for _, r := range res {
					valid = test.valid(r.(*viewer.Item))
				}
				require.True(t, valid, "all results should match the search criteria")
			}
		})
	}
}

// validateSorting checks whether or not results are sorted by a particular column
func validateSorting(items []list.Item, field func(*viewer.Item) float64, sorted func(float64, *viewer.Item) (float64, bool)) bool {
	var current float64
	for i, item := range items {
		if i == 0 {
			// set the initial value by getting the right field for the first item
			current = field(item.(*viewer.Item))
		}
		res, ok := item.(*viewer.Item)
		if !ok {
			return false
		}

		// check if this item follows the sorting direction
		nextVal, isSorted := sorted(current, res)
		if !isSorted {
			return false
		}
		// update the current value
		current = nextVal
	}
	return true
}
