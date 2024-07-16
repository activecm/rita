package viewer

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var DebugMode bool
var mainStyle = lipgloss.NewStyle().Margin(0, 0)

type Model struct {
	// keys      keys.KeyMap
	minTS          time.Time
	SearchBar      *searchModel
	SideBar        sidebarModel
	List           listModel
	searchValue    string
	Footer         footerModel
	dbFooterBar    string
	title          string
	db             *database.DB
	serverPageSize int // the number of items per server "page", this is not the same as the list page size
	serverPage     int // the current server-side page, this is not the same as the current list page

	keys           keyMap
	width          int
	ViewSearchHelp bool
	ViewHelp       bool
}

type keyMap struct {
	base           list.KeyMap
	enter          key.Binding
	filter         key.Binding
	clearFilter    key.Binding
	clearSearchBar key.Binding
	unfocusFilter  key.Binding
	toggleScroll   key.Binding
	quit           key.Binding
}

type column struct {
	name  string
	width int
}

// CreateUI creates the terminal UI
func CreateUI(_ *config.Config, db *database.DB, useCurrentTime bool, maxTimestamp time.Time, minTimestamp time.Time) error {
	// create model
	m, err := NewModel(maxTimestamp, minTimestamp, useCurrentTime, db)
	if err != nil {
		return err
	}

	// create program
	p := tea.NewProgram(m, tea.WithAltScreen())

	// run the program
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running program: %w", err)
	}

	return nil
}

func NewModel(maxTimestamp, minTimestamp time.Time, useCurrentTime bool, db *database.DB) (*Model, error) {
	pageSize := 100
	// get results from database
	rows, _, err := GetResults(db, &Filter{}, 0, pageSize, minTimestamp)
	if err != nil {
		return nil, err
	}

	// set columns
	columns := []column{{"Severity", 14}, {"Source", 20}, {"Destination", 30}, {"Beacon", 10}, {"Duration", 15}, {"Subdomains", 15}, {"Threat Intel", 15}}

	// set table size
	width := getTableWidth(columns)
	height := 20

	// create dataList
	dataList := MakeList(rows, columns, width, height)

	// create search bar
	searchBar := NewSearchModel("", width)

	// create side bar
	sideBar := NewSidebarModel(maxTimestamp, useCurrentTime, &Item{})
	if len(dataList.Rows.Items()) > 0 {
		// set sidebar data to whichever item is selected in the list
		data, ok := dataList.Rows.Items()[dataList.Rows.Index()].(Item)
		if !ok {
			return nil, fmt.Errorf("error setting sidebar data")
		}
		sideBar.Data = &data

	}

	// create footer
	footer := NewFooterModel(db.GetSelectedDB())

	// create model
	m := &Model{
		minTS:          minTimestamp,
		List:           dataList,
		SearchBar:      &searchBar,
		SideBar:        sideBar,
		serverPageSize: pageSize,
		Footer:         footer,
		db:             db,
		width:          width,
	}

	// initialize model components
	m.Init()

	// initialize sidebar
	m.SideBar.Init()

	// create terminal ui model
	return m, nil
}

func (m *Model) Init() tea.Cmd {

	// set title
	m.title = getTitle()

	// set key bindings
	m.keys.base = list.DefaultKeyMap()
	m.keys.enter = key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "apply filter"),
	)
	m.keys.filter = key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "filter"),
	)

	m.keys.clearFilter = key.NewBinding(
		key.WithKeys("ctrl+x"),
		key.WithHelp("ctrl+x", "clear filter"),
	)

	m.keys.clearSearchBar = key.NewBinding(
		key.WithKeys("ctrl+x"),
		key.WithHelp("ctrl+x", "clear filter"),
	)

	m.keys.unfocusFilter = key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "cancel search"),
	)

	m.keys.toggleScroll = key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "toggle sidebar scrolling"),
	)

	m.keys.quit = key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q | ctrl+c", "quit"),
	)

	return m.Footer.spinner.Tick
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// make the footer the entire width of the terminal
		m.Footer.width = msg.Width

		// make the list fill the extra vertical space
		m.List.SetHeight(msg.Height - int(math.Max(float64(lipgloss.Height(m.SearchBar.View())), float64(lipgloss.Height(m.title)))) - lipgloss.Height(m.dbFooterBar))

		// make the sidebar the same height as the list
		m.SideBar.Viewport.Height = m.List.totalHeight

		// make sidebar fill the extra horizontal space
		m.SideBar.Viewport.Width = msg.Width - lipgloss.Width(m.List.View()) - 4

		// make search bar the same width as the list
		m.SearchBar.width = m.List.width

	case tea.KeyMsg:
		switch {
		// toggle search help
		case key.Matches(msg, m.keys.base.ShowFullHelp):
			// toggle search help if search bar is focused and main help text isn't displayed
			if m.SearchBar.TextInput.Focused() && !m.ViewHelp {
				m.ViewSearchHelp = !m.ViewSearchHelp
			} else {
				// toggle main search help
				m.ViewHelp = !m.ViewHelp
			}

		// focus search bar
		case key.Matches(msg, m.keys.filter):
			m.SearchBar.Focus()

		// toggle sidebar scrolling
		case key.Matches(msg, m.keys.toggleScroll):
			m.SideBar.ScrollEnabled = !m.SideBar.ScrollEnabled

		// handle filtering
		case m.SearchBar.TextInput.Focused():
			cmd = m.handleFiltering(msg)

		// clear filtering (when search bar not focused)
		case key.Matches(msg, m.keys.clearFilter):
			m.resetFiltering()

		// handle quiting
		case key.Matches(msg, m.keys.quit):
			cmd = tea.Quit

		// otherwise, handle browsing
		default:
			cmd = m.handleBrowsing(msg)
		}
	case StillLoadingResults, FooterFlash:
		_, cmd = m.Footer.Update(msg)
	case FinishedLoadingResults:

	case spinner.TickMsg:
		m.Footer.spinner, cmd = m.Footer.spinner.Update(msg)
	}

	// update sidebar

	// verify that there are items to display
	if len(m.List.Rows.Items()) > 0 {
		// adjust index to the last item if out of range
		if m.List.Rows.Index() >= len(m.List.Rows.Items()) {
			index := len(m.List.Rows.Items()) - 1
			m.List.Rows.Select(index)
		}

		// adjust cursor to the last item on the page if out of range
		if m.List.Rows.Cursor() >= m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) {
			index := (m.List.Rows.Paginator.Page * m.List.Rows.Paginator.PerPage) + m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) - 1
			m.List.Rows.Select(index)
		}

		if data, ok := m.List.Rows.Items()[m.List.Rows.Index()].(Item); ok {
			m.SideBar.Data = &data
		}

	} else {
		m.SideBar.Data = &Item{}
	}

	return m, cmd
}

// View renders the model to the terminal
func (m *Model) View() string {
	// set the database header

	var mainContent string
	switch {
	case m.ViewSearchHelp:
		mainContent = helpPanel(m.SideBar.Viewport.Height, m.List.width, searchHelpText())
	case m.ViewHelp:
		mainContent = helpPanel(m.SideBar.Viewport.Height, m.List.width, mainHelpText())
	default:
		mainContent = lipgloss.JoinHorizontal(
			lipgloss.Left,
			mainStyle.Render(m.List.View()),
			mainStyle.Render(m.SideBar.View()),
		)
	}

	// join and render header, searchbar, main view, and footer
	return lipgloss.JoinVertical(lipgloss.Top,
		lipgloss.JoinHorizontal(lipgloss.Left, mainStyle.Render(m.SearchBar.View()), m.title),
		mainContent,
		m.Footer.View(),
	)
}

type FinishedLoadingResults string
type StillLoadingResults string

// handleFiltering handles key presses on the search bar
func (m *Model) handleFiltering(msg tea.KeyMsg) tea.Cmd {
	var cmd tea.Cmd
	switch {

	// unfocus the search bar
	case key.Matches(msg, m.keys.unfocusFilter):
		// if help is toggled, untoggle it
		if m.ViewSearchHelp {
			m.ViewSearchHelp = false
		}
		// unfocus search bar
		m.SearchBar.Blur()

	// filter results
	case key.Matches(msg, m.keys.enter):
		if m.SearchBar.searchErr == "" {
			m.SearchBar.Blur()
			return func() tea.Msg {
				m.requestResults(false)
				finishedCmd := FinishedLoadingResults("success")
				return finishedCmd

			}
		}

	// clear filtering (when search bar is focused)
	case key.Matches(msg, m.keys.clearSearchBar):
		m.SearchBar.TextInput.Reset()

	// otherwise, update the search bar with what the user is typing
	default:
		m.SearchBar, cmd = m.SearchBar.Update(msg)
		m.searchValue = m.SearchBar.Value()
		m.SearchBar.ValidateSearchInput()
	}

	return cmd

}

// handleBrowsing handles key presses on list
func (m *Model) handleBrowsing(msg tea.KeyMsg) tea.Cmd {
	var cmd tea.Cmd
	// if sidebar scrolling is enabled, pass key events through to the sidebar and
	// ignore them for all other components
	if m.SideBar.ScrollEnabled {
		m.SideBar.Viewport, cmd = m.SideBar.Viewport.Update(msg)
	} else {
		switch {
		// go to the previous row
		case key.Matches(msg, m.keys.base.CursorUp):
			m.List.Rows.CursorUp()

		// go to the next row
		case key.Matches(msg, m.keys.base.CursorDown):
			m.List.Rows.CursorDown()

		// go to the previous page
		case key.Matches(msg, m.keys.base.PrevPage):
			m.List.Rows.Paginator.PrevPage()

		// go to the next page
		case key.Matches(msg, m.keys.base.NextPage):
			if m.List.Rows.Paginator.Page == m.List.Rows.Paginator.TotalPages-1 {
				if !m.Footer.loading {
					m.Footer.loading = true
					return func() tea.Msg {
						m.serverPage++
						m.requestResults(true)
						finishedCmd := FinishedLoadingResults("success")
						return finishedCmd
					}
				}
				// trigger the footer to flash if the user
				// continues to navigate to the next page if the results are still loading
				return func() tea.Msg {
					return StillLoadingResults("yeah")
				}
			}
			m.List.Rows.Paginator.NextPage()

			// set selected row to the last item on the page if keeping the cursor on the same row
			// as the previous page would result in the cursor being out of bounds
			if m.List.Rows.Cursor() >= m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) {
				index := (m.List.Rows.Paginator.Page * m.List.Rows.Paginator.PerPage) + m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) - 1
				m.List.Rows.Select(index)
			}

		// go to the first page
		case key.Matches(msg, m.keys.base.GoToStart):
			m.List.Rows.Paginator.Page = 0

		// go to the last page
		case key.Matches(msg, m.keys.base.GoToEnd):
			m.List.Rows.Paginator.Page = m.List.Rows.Paginator.TotalPages - 1

			// set selected row to the last item on the page if keeping the cursor on the same row
			// as the previous page would result in the cursor being out of bounds
			if m.List.Rows.Cursor() >= m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) {
				m.List.Rows.Select(len(m.List.Rows.Items()) - 1)
			}
		}
	}
	return cmd

}

// requestResults queries the database for results based on the search bar filter
func (m *Model) requestResults(appendResults bool) {

	// get filter from search bar
	filter := m.SearchBar.Filter()

	// query database for results
	if m.SearchBar.searchErr == "" {
		// set loading spinner to true
		m.Footer.loading = true
		// time.Sleep(4 * time.Second)

		// get results from database
		items, appliedFilter, err := GetResults(m.db, filter, m.serverPage, m.serverPageSize, m.minTS)
		if err != nil {
			m.List.Rows.SetItems([]list.Item{})
			m.Footer.ErrMsg = "Error fetching results: " + err.Error()
		}

		// set loading spinner to false
		m.Footer.loading = false

		// reset cursor to the first item if a search was applied
		if appliedFilter {
			m.List.Rows.Select(0)
		}

		// set items in list
		if appendResults {
			m.List.Rows.SetItems(append(m.List.Rows.Items(), items...))
		} else {
			m.List.Rows.SetItems(items)
		}
	}

}

// resetFiltering resets the filtering and gets unfiltered results
func (m *Model) resetFiltering() {
	m.SearchBar.TextInput.Reset()
	m.SearchBar.searchErr = ""
	m.requestResults(false)
}

// getTitle returns the title of the application
func getTitle() string {
	return mainStyle.
		MarginLeft(1).MarginTop(3).
		// DO NOT INDENT THE FOLLOWING CODE BLOCK!
		Render(`
░█▀▀█ ▀█▀ ▀▀█▀▀ ─█▀▀█
░█▄▄▀ ░█─ ─░█── ░█▄▄█
░█─░█ ▄█▄ ─░█── ░█─░█ by Active Countermeasures©
`)

}

// searchHelpText returns the help text for the search bar
func searchHelpText() string {
	// return ""
	var helpText string
	subtitleStyle := lipgloss.NewStyle().Foreground(overlay2)
	helpStyle := lipgloss.NewStyle().Foreground(surface0)
	helpText += lipgloss.NewStyle().Foreground(subtext0).Render("Search Examples")
	// footer = lipgloss.JoinVertical(lipgloss.Top, footer, subtitleStyle.Render("RITA supports a similar search syntax to GitHub."))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, "", subtitleStyle.Render("Filter by column:"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("severity:high"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("src:192.168.5.2"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("beacon:>80"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("threat_intel:true"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("duration:2h45m"))

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, "", subtitleStyle.Render("Sort by column:"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("sort:severity-asc"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("sort:beacon-desc"))

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, "", subtitleStyle.Render("Supported search columns:"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("◦ severity"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("◦ beacon"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("◦ duration"))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render("◦ subdomains"))

	headers := []string{"Column", "Field", "Operators", "Data Type"}

	data := [][]string{
		{"Severity", "severity", "", "critical|high|medium|low"},
		{"Source", "src", "", "IP address"},
		{"Destination", "dst", "", "IP address or FQDN"},
		{"Beacon Score", "beacon", ">,>=,<,<=", "whole number"},
		{"Duration", "duration", ">,>=,<,<=", "string, ex:(2h45m)"},
		{"Subdomains", "subdomains", ">,>=,<,<=", "whole number"},
		{"Threat Intel", "threat_intel", "", "true|false"},
	}

	// row indices (starting from 1 because 0 is the header) to highlight in the data type column
	dataTypesToHighlight := []int{1, 7}

	codeStyle := lipgloss.NewStyle().Background(surface0).Foreground(peach).ColorWhitespace(false)
	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("238"))).
		Headers(headers...).
		BorderRow(true).
		Width(80).
		Rows(data...).
		StyleFunc(func(row, col int) lipgloss.Style {
			// style fields with pseudo-code highlighting style
			if row > 0 { // skip the header
				if col == 1 || col == 2 || (col == 3 && slices.Contains(dataTypesToHighlight, row)) {
					return codeStyle
				}
				return lipgloss.NewStyle()
			}
			// header style
			return lipgloss.NewStyle().Foreground(lavender).Bold(true)
		})

	tableHeader := lipgloss.NewStyle().Foreground(mauve).Bold(true).Render("Supported Search Fields")
	tableFooter := lipgloss.JoinVertical(lipgloss.Top,
		lipgloss.NewStyle().Foreground(subtext0).PaddingLeft(1).Render("Multiple search criteria are separated by a space. For example:"),
		lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(surface0).Render("src:192.168.88.2 dst:165.225.88.16 beacon:>=90 sort:duration-desc"),
	)
	tt := lipgloss.JoinVertical(lipgloss.Top, tableHeader, t.Render(), lipgloss.NewStyle().MarginTop(1).Render(tableFooter))

	x := lipgloss.JoinHorizontal(lipgloss.Left, helpText, lipgloss.NewStyle().MarginLeft(5).Render(tt))
	return lipgloss.NewStyle().Margin(1, 0, 0, 2).Render(x)

}

// mainHelpText returns the help text for the main program
func mainHelpText() string {
	// var helpText string
	// subtitleStyle := lipgloss.NewStyle().Foreground(overlay2)
	helpStyle := lipgloss.NewStyle().Foreground(overlay2)
	subduedHelpStyle := lipgloss.NewStyle().Foreground(surface0)
	sectionStyle := lipgloss.NewStyle().Foreground(lavender).Bold(true)
	subSectionStyle := lipgloss.NewStyle().Foreground(subtext0)
	helpText := lipgloss.JoinVertical(lipgloss.Top,
		sectionStyle.Render("Navigation"),
		"",
		subSectionStyle.Render("Table"),
	)
	// helpText = lipgloss.NewStyle().Foreground(subtext0).Bold(true).Render("Navigation")

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("↑/k"), subduedHelpStyle.Render("previous row"),
		subduedHelpStyle.Render(bullet),
		helpStyle.Render("↓/j"), subduedHelpStyle.Render("next row")))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("←/h"), subduedHelpStyle.Render("previous page"),
		subduedHelpStyle.Render(bullet),
		helpStyle.Render("→/l"), subduedHelpStyle.Render("next page")),
	)
	helpText += subSectionStyle.Render("\n\nSidefeed")
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("tab"), subduedHelpStyle.Render("toggle scrolling")))
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("↑/k"), subduedHelpStyle.Render("scroll up"),
		subduedHelpStyle.Render(bullet),
		helpStyle.Render("↓/j"), subduedHelpStyle.Render("scroll down")))
	pgDownSidebar := "pgdn/f"
	pgUpSidebar := "pgup/b"
	if runtime.GOOS == "darwin" {
		pgDownSidebar = "fn+↓"
		pgUpSidebar = "fn+↑"
	}
	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render(pgDownSidebar), subduedHelpStyle.Render("page down"),
		subduedHelpStyle.Render(bullet),
		helpStyle.Render(pgUpSidebar), subduedHelpStyle.Render("page up")))

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText,
		sectionStyle.Render("\n\nShortcuts"))

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("q/ctrl+c"), subduedHelpStyle.Render("quit"),
		subduedHelpStyle.Render(bullet),
		helpStyle.Render("?"), subduedHelpStyle.Render("toggle help")),
	)

	helpText = lipgloss.JoinVertical(lipgloss.Top, helpText, helpStyle.Render(
		helpStyle.Render("ctrl+x"), subduedHelpStyle.Render("clear filter"),
	))

	return lipgloss.NewStyle().Margin(1, 0, 0, 2).Render(helpText)

}

func helpPanel(height int, width int, contents string) string {
	return mainStyle.Height(height).Width(width).
		Border(lipgloss.RoundedBorder()).BorderForeground(surface0).
		Render(contents)
}

func getTableWidth(columns []column) int {
	width := 0
	for _, column := range columns {
		width += column.width
	}

	return width
}
