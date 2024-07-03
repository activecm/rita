package viewer

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/activecm/rita/config"
	"github.com/activecm/rita/util"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	operatorRegex = regexp.MustCompile(`^(?P<operator>[><]=?)?(?P<value>(\d|[A-Za-z.])+)$`)

	validSeverities = map[string]bool{
		string(config.CriticalThreat): true,
		string(config.HighThreat):     true,
		string(config.MediumThreat):   true,
		string(config.LowThreat):      true,
	}

	allowedSortColumns = []string{"severity", "beacon", "duration", "subdomains"}

	numericalColumns = []string{"count", "beacon", "subdomains"}

	// any columns in percentage columns must also be listed in numerical columns
	percentageColumns = []string{"beacon"}

	timeColumns = []string{"duration"}

	stringColumns = []string{"src", "dst", "severity", "sort", "threat_intel"}
)

var searchStyle = lipgloss.NewStyle().MarginTop(3)

type OperatorFilter struct {
	Operator string
	Value    string
}
type Filter struct {
	Src            string
	Dst            string
	Fqdn           string
	Severity       []OperatorFilter
	Count          OperatorFilter
	Beacon         OperatorFilter
	Duration       OperatorFilter
	Subdomains     OperatorFilter
	ThreatIntel    string
	SortSeverity   string
	SortBeacon     string
	SortDuration   string
	SortSubdomains string
	// For testing
	LastSeen     time.Time
	SortLastSeen string
}

type searchModel struct {
	initialValue string
	TextInput    textinput.Model
	width        int
	searchErr    string
	// filters      Filter
}

func NewSearchModel(initialValue string, width int) searchModel {
	// prompt := fmt.Sprintf(" is:%s ", sectionType)
	// prompt := "hello world"
	// prompt := "Search:"
	ti := textinput.New()
	ti.Placeholder = ""
	ti.Focus()
	// ti.Width = getInputWidth(width, prompt)
	ti.PromptStyle = ti.PromptStyle.Copy().Foreground(mauve)
	// ti.Prompt = prompt
	ti.TextStyle = ti.TextStyle.Copy().Faint(true)
	ti.Blur()
	ti.SetValue(initialValue)
	ti.CursorStart()

	return searchModel{
		TextInput:    ti,
		initialValue: initialValue,
		width:        width,
		// sectionType:  sectionType,
	}
}

func (m searchModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m searchModel) Update(msg tea.Msg) (searchModel, tea.Cmd) {
	var cmd tea.Cmd
	m.TextInput, cmd = m.TextInput.Update(msg)
	return m, cmd
}

func (m searchModel) View() string {
	helpStyle := lipgloss.NewStyle().Foreground(overlay0)
	subduedHelpStyle := lipgloss.NewStyle().Foreground(surface0)
	var label string
	if m.searchErr != "" {
		m.TextInput.Prompt = ""
		label = lipgloss.NewStyle().Foreground(red).Render(m.searchErr)
	} else {
		if m.TextInput.Focused() {
			m.TextInput.Prompt = ""
			label = lipgloss.JoinHorizontal(lipgloss.Left,
				helpStyle.Render("enter"),
				" ",
				subduedHelpStyle.Render("submit"),
				" ",
				subduedHelpStyle.Render(bullet),
				" ",
				helpStyle.Render("esc"),
				" ",
				subduedHelpStyle.Render("cancel search"),
				" ",
				subduedHelpStyle.Render(bullet),
				" ",
				helpStyle.Render("ctrl+x"),
				" ",
				subduedHelpStyle.Render("clear"),
				" ",
				subduedHelpStyle.Render(bullet),
				" ",
				helpStyle.Render("?"),
				" ",
				subduedHelpStyle.Render("toggle help"),
			)

		} else {
			label = helpStyle.Render("press / to begin search")
			if m.TextInput.Value() == "" {
				m.TextInput.Prompt = "Search: "
			} else {

				label = lipgloss.JoinHorizontal(lipgloss.Left,
					label,
					" ",
					subduedHelpStyle.Render("edit"),
					" ",
					subduedHelpStyle.Render(bullet),
					" ",
					helpStyle.Render("ctrl+x"),
					" ",
					subduedHelpStyle.Render("clear filter"),
				)
				m.TextInput.Prompt = ""
			}
		}
	}
	help := lipgloss.NewStyle().
		MarginLeft(1).
		Foreground(helpTextColor).
		Render(label)
	input := lipgloss.NewStyle().
		Width(m.width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(overlay0).
		Render(m.TextInput.View())

	return searchStyle.Render(lipgloss.JoinVertical(lipgloss.Top, help, input))
}

func (m *searchModel) Focus() {
	m.TextInput.TextStyle = m.TextInput.TextStyle.Copy().Faint(false)
	m.TextInput.CursorEnd()
	m.TextInput.Focus()
}

func (m *searchModel) Blur() {
	m.TextInput.TextStyle = m.TextInput.TextStyle.Copy().Faint(true)
	m.TextInput.Blur()
}

func (m searchModel) HasError() bool {
	return m.searchErr != ""
}

func (m *searchModel) SetValue(val string) {
	m.TextInput.SetValue(val)
}

func (m *searchModel) Value() string {
	return m.TextInput.Value()
}

func (m *searchModel) ValidateSearchInput() {
	// reset search error and check for commas as user is typing
	switch {
	case strings.Contains(m.Value(), ","):
		m.searchErr = "commas are not supported"
	default:
		m.searchErr = ""

	}

	// split input on space to make sure user was finished entering a search field before validating
	split := strings.Split(m.Value(), " ")
	if len(split) > 1 {
		// parse search input for errors
		if _, err := ParseSearchInput(m.Value()); err != "" {
			m.searchErr = err
		}
	}
}

func (m *searchModel) Filter() Filter {
	filter, err := ParseSearchInput(m.TextInput.Value())
	if err != "" {
		m.searchErr = err
	}
	return filter
}

// ParseSearchInput parses the search input and returns a filter  struct
func ParseSearchInput(input string) (Filter, string) {
	// create a new filter struct
	criteria := Filter{}

	// return an empty filter if input is empty
	if input == "" {
		return Filter{}, ""
	}

	// check for commas in the input
	if strings.Contains(input, ",") {
		return Filter{}, "commas are not supported"
	}

	// split input into field-value pairs
	pairs := strings.Fields(input)

	for _, input := range pairs {
		// skip validation if there was a space at the end of the search
		if input == "" {
			continue
		}

		// verify the search uses the proper colon-separated syntax
		if !strings.Contains(input, ":") {
			return Filter{}, "column name and value must be separated by a colon"
		}

		// split the input into field and value
		split := strings.SplitN(input, ":", 2)
		field := split[0]
		value := split[1]

		// parse the field and value of valid search columns
		switch {
		// --- validate numerical columns
		case slices.Contains(numericalColumns, field):

			// parse operator and value from input
			operator, number, parseErr := parseSearchOperator(field, value)
			if parseErr != "" {
				return Filter{}, parseErr
			}

			// validate number is a true number
			numberInt, err := strconv.Atoi(number)
			if err != nil {
				return Filter{}, field + " must be a valid number"
			}

			// validate and format number to percentage (float from 0-1) for percentage columns
			if slices.Contains(percentageColumns, field) {
				// don't allow values over 100%
				if numberInt > 100 {
					return Filter{}, field + " can't be greater than 100"
				}
				percentage := float32(numberInt) / 100
				// divide value by 100 to convert to decimal, must be formatted to two places
				number = fmt.Sprintf("%1.2f", percentage)
			}

			// parse and set the operator
			var searchVal OperatorFilter
			if operator == "" {
				// add equals sign when no operator was captured
				searchVal.Operator = "="
			} else {
				searchVal.Operator = operator
			}

			// set the value
			searchVal.Value = number

			// assign parsed values to the corresponding field in criteria
			switch field {
			case "count":
				criteria.Count = searchVal
			case "beacon":
				criteria.Beacon = searchVal
			case "subdomains":
				criteria.Subdomains = searchVal
			}

		// --- validate time columns
		case slices.Contains(timeColumns, field):

			// parse operator and time string from value
			operator, input, parseErr := parseSearchOperator(field, value)
			if parseErr != "" {
				return Filter{}, parseErr
			}

			fmt.Println("operator:", operator, "input", input, "parseErr", parseErr)

			// validate time string is valid
			duration, err := time.ParseDuration(input)
			if err != nil {
				parseErr = field + " must be a valid time in the format '10s', '1.5h', '2h45m', etc. Valid units are 's', 'm', 'h'"
				return Filter{}, parseErr
			}

			// assign operator to criteria
			if operator == "" {
				// add equals sign when no operator was captured
				criteria.Duration.Operator = "="
			} else {
				criteria.Duration.Operator = operator
			}

			// convert duration to seconds and assign to criteria
			criteria.Duration.Value = fmt.Sprintf("%.0f", duration.Seconds())

		// --- validate string columns
		case slices.Contains(stringColumns, field):
			switch field {
			case "src":
				// validate string is IP address
				if _, err := netip.ParseAddr(value); err != nil {
					return Filter{}, "src must be a valid IP address"
				}
				criteria.Src = value

			case "dst":
				// validate if string is IP address
				if _, err := netip.ParseAddr(value); err != nil {
					// if value is not an IP, check for valid FQDN
					if util.ValidFQDN(value) {
						criteria.Fqdn = value
					} else {
						return Filter{}, "dst must be a valid IP address or FQDN"
					}
				} else {
					criteria.Dst = value
				}
			case "threat_intel":
				filter, err := strconv.ParseBool(value)
				if err != nil {
					return Filter{}, "threat_intel must be true or false"
				}
				if filter {
					criteria.ThreatIntel = "true"
				} else {
					criteria.ThreatIntel = "false"
				}
			case "sort": // sort:severity-asc
				// split the column from the sort direction
				sortSplit := strings.Split(value, "-")
				if len(sortSplit) != 2 {
					return Filter{}, "sort value must contain one hyphen, in the format sort:<column>-<direction>"
				}

				// validate sort column and direction
				column := sortSplit[0]
				direction := sortSplit[1]

				// make sure this column has sorting enabled
				if !slices.Contains(allowedSortColumns, column) {
					return Filter{}, "invalid sort column"
				}

				// validate sort direction
				if direction != "asc" && direction != "desc" {
					return Filter{}, "sort direction must be either asc or desc"
				}

				// assign sort column and direction to criteria
				switch column {
				case "severity":
					criteria.SortSeverity = direction
				case "beacon":
					criteria.SortBeacon = direction
				case "duration":
					criteria.SortDuration = direction
				case "subdomains":
					criteria.SortSubdomains = direction
				}

			case "severity":
				// check if the value is a valid severity
				category := config.ImpactCategory(value)
				err := config.ValidateImpactCategory(category)

				// if the severity is not critical, check for errors
				// The critical category is not included in the ValidateImpactCategory function because
				// the final score only reaches the Critical category if it exceeds the high threshold
				// via modifiers, so users aren't able to set assign threat categories in the config to critical
				// We also do not want to allow users to filter by the None category
				if err != nil && category != config.CriticalThreat || category == config.NoneThreat {
					return Filter{}, "invalid category, must be 'critical', 'high', 'medium', or 'low'"
				}

				// assign severity to criteria and set the needed operators for querying
				switch category {
				case config.CriticalThreat:
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: ">",
						Value:    fmt.Sprint(config.HIGH_CATEGORY_SCORE),
					})
				case config.HighThreat:
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: "<=",
						Value:    fmt.Sprint(config.HIGH_CATEGORY_SCORE),
					})
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: ">=",
						Value:    fmt.Sprint(config.MEDIUM_CATEGORY_SCORE),
					})
				case config.MediumThreat:
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: "<",
						Value:    fmt.Sprint(config.MEDIUM_CATEGORY_SCORE),
					})
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: ">=",
						Value:    fmt.Sprint(config.LOW_CATEGORY_SCORE),
					})
				case config.LowThreat:
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: "<",
						Value:    fmt.Sprint(config.LOW_CATEGORY_SCORE),
					})
					criteria.Severity = append(criteria.Severity, OperatorFilter{
						Operator: ">=",
						Value:    fmt.Sprint(config.NONE_CATEGORY_SCORE),
					})
				}

			}
		default:
			return Filter{}, "please reference a valid search column"
		}

	}
	// panic(fmt.Sprintf("end of function criteria: %+v", criteria))

	return criteria, ""
}

func parseSearchOperator(field string, value string) (string, string, string) {
	var operator, number, err string

	// make sure the entire string matches the regex
	if !operatorRegex.MatchString(value) {
		err = fmt.Sprintf("%s value must be %s:<value> or %s:<operator><value>, where <operator> is one of >, <, >=, <=", field, field, field)
		return operator, number, err
	}

	matches := operatorRegex.FindStringSubmatch(value)
	if matches == nil {
		// no match, bad, this should not happen because we're matching the string above
		err = field + " value is not parseable"
		return operator, number, err
	}

	// extract operator from regex capture
	operator = matches[operatorRegex.SubexpIndex("operator")]

	// extract number value from regex capture
	number = matches[operatorRegex.SubexpIndex("value")]

	return operator, number, err
}
