package viewer

import (
	"fmt"
	"io"

	"github.com/activecm/rita/v5/config"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/truncate"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// colors
var (
	defaultTextColor = lipgloss.AdaptiveColor{Light: "#2c2b2f", Dark: "#d3cdd4"}
	subduedTextColor = lipgloss.AdaptiveColor{Light: "#454545", Dark: "#A49FA5"}
	helpTextColor    = lipgloss.AdaptiveColor{Light: "#DDDADA", Dark: "#3C3C3C"}
	separatorColor   = lipgloss.AdaptiveColor{Light: "#0BA4B8", Dark: "#AD58B4"}

	// catpuccin theme colors
	red      = lipgloss.AdaptiveColor{Light: "#D2042D", Dark: "#f38ba8"} //  "#ff1f7c" "#D2042D" "#eb2654"
	peach    = lipgloss.AdaptiveColor{Light: "#fe640b", Dark: "#fab387"}
	yellow   = lipgloss.AdaptiveColor{Light: "#df8e1d", Dark: "#f9e2af"}
	lavender = lipgloss.AdaptiveColor{Light: "#7287fd", Dark: "#b4befe"}
	mauve    = lipgloss.AdaptiveColor{Light: "#8839ef", Dark: "#cba6f7"}
	sapphire = lipgloss.AdaptiveColor{Light: "#209fb5", Dark: "#74c7ec"}
	green    = lipgloss.AdaptiveColor{Light: "#40a02b", Dark: "#a6e3a1"}
	pink     = lipgloss.AdaptiveColor{Light: "#ea76cb", Dark: "#f5c2e7"}

	overlay0 = lipgloss.AdaptiveColor{Light: "#9ca0b0", Dark: "#6c7086"}
	surface0 = lipgloss.AdaptiveColor{Light: "#ccd0da", Dark: "#313244"}
	base     = lipgloss.AdaptiveColor{Light: "#eff1f5", Dark: "#1e1e2e"}
	overlay2 = lipgloss.AdaptiveColor{Light: "#7c7f93", Dark: "#9399b2"}

	subtext0 = lipgloss.AdaptiveColor{Light: "#6c6f85", Dark: "#a6adc8"}
)

// styles
var (
	listStyle       = lipgloss.NewStyle().Margin(0, 0)
	listHeaderStyle = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(lavender).Foreground(subduedTextColor).MarginBottom(1)
)

const (
	bullet   = "•"
	ellipsis = "…"
)

type listModel struct {
	Rows        list.Model
	width       int
	totalHeight int
	columns     []column
}

func MakeList(items []list.Item, columns []column, width int, height int) listModel {
	d := listDelegate{delegate: list.NewDefaultDelegate(), columns: columns}

	l := list.New(items, d, width, height)

	l.SetShowStatusBar(false)
	l.SetShowTitle(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)

	return listModel{
		Rows:    l,
		columns: columns,
		width:   width,
	}
}

func (m *listModel) Init() tea.Cmd {
	return nil
}

func (m *listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	// handle window resize
	if _, ok := msg.(tea.WindowSizeMsg); ok {
		_, v := listStyle.GetFrameSize()
		m.Rows.SetSize(m.width, m.Rows.Height()-v)
	}

	var cmd tea.Cmd

	m.Rows, cmd = m.Rows.Update(msg)
	return m, cmd
}

func (m *listModel) SetHeight(height int) {
	_, v := listStyle.GetFrameSize()
	header := lipgloss.Height(renderColumnHeader(m.columns, m.width))
	h := (height - header - v)
	m.totalHeight = header + v + h
	m.Rows.SetSize(m.width, h)
	m.Rows.SetHeight(h)
}

func (m *listModel) View() string {

	header := renderColumnHeader(m.columns, m.width)

	return listStyle.
		Border(lipgloss.RoundedBorder(), true, false, true, true).
		BorderForeground(lavender).
		Render(lipgloss.JoinVertical(lipgloss.Top, header, m.Rows.View()))
}

type listDelegate struct {
	delegate list.DefaultDelegate
	columns  []column
}

func (d listDelegate) Height() int                             { return 2 }   //nolint:gocritic // bubbletea requires these to not be pointer methods
func (d listDelegate) Spacing() int                            { return 1 }   //nolint:gocritic // bubbletea requires these to not be pointer methods
func (d listDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil } //nolint:gocritic // bubbletea requires these to not be pointer methods
func (d listDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) { //nolint:gocritic // bubbletea requires these to not be pointer methods

	var (
		severity      string
		src, dst      string
		beacon        string
		totalDuration string
		subdomains    string
		threatIntel   string
	)

	// get the item
	i, ok := listItem.(*Item)
	if !ok {
		return
	}

	severity = i.GetSeverity(true)
	src = i.GetSrc()
	dst = i.GetDst()
	beacon = i.GetBeacon()
	totalDuration = i.GetTotalDuration()
	subdomains = i.GetSubdomains()
	threatIntel = i.GetThreatIntel()

	if m.Width() <= 0 {
		// short-circuit
		return
	}

	// conditions
	var (
		isSelected = index == m.Index()
	)

	// build list item out of pieces and style/color them accordingly

	// set up language specific printer
	p := message.NewPrinter(language.English)

	// set up the style for the row, giving each cell a right padding of 3 to keep them from running together
	style := lipgloss.NewStyle().PaddingRight(3)

	// set the background color of the row if it is selected
	if isSelected {
		style = style.Background(surface0).Bold(true)
	}

	// get severity
	categoryStyle := style.PaddingLeft(2).Width(d.columns[0].width)
	categoryTitle := categoryStyle.Render(Truncate(severity, &categoryStyle))

	// get source
	srcStyle := style.Foreground(defaultTextColor).Width(d.columns[1].width)
	srcTitle := srcStyle.Render(Truncate(src, &srcStyle))

	// get destination
	dstStyle := style.Foreground(defaultTextColor).Width(d.columns[2].width)
	dstTitle := dstStyle.Render(Truncate(dst, &dstStyle))

	// get beacon
	beaconStyle := style.Width(d.columns[3].width)
	beaconTitle := beaconStyle.Render(beacon)

	// get total duration
	totalDurationStyle := style.Width(d.columns[4].width)
	totalDurationTitle := totalDurationStyle.Render(totalDuration)

	// get subdomains
	subdomainsStyle := style.Width(d.columns[5].width)
	subDomainsTitle := subdomainsStyle.Render(p.Sprint(subdomains))

	// get threat intel
	threatIntelStyle := style.Width(d.columns[6].width)
	threatIntelTitle := threatIntelStyle.Render(p.Sprint(threatIntel))

	// render the full row
	row := lipgloss.NewStyle().Render(
		lipgloss.JoinHorizontal(lipgloss.Left, categoryTitle, srcTitle, dstTitle, beaconTitle, totalDurationTitle, subDomainsTitle, threatIntelTitle),
	)

	separator := lipgloss.NewStyle().MarginLeft(1).Width(m.Width()+1).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(separatorColor).Render()
	_ = separator

	fmt.Fprintf(w, "%s", row)
}

func Truncate(str string, style *lipgloss.Style) string {
	// Prevent text from exceeding list width
	textwidth := uint(style.GetWidth() - style.GetPaddingLeft() - style.GetPaddingRight())
	return truncate.StringWithTail(str, textwidth, ellipsis)
}

func renderIndicator(score float32, displayText string) string {
	category := config.GetImpactCategoryFromScore(score)
	style := lipgloss.NewStyle()

	switch category {
	case config.CriticalThreat:
		return style.Foreground(red).Render(displayText)
	case config.HighThreat:
		return style.Foreground(peach).Render(displayText)
	case config.MediumThreat:
		return style.Foreground(yellow).Render(displayText)
	case config.LowThreat:
		return style.Foreground(sapphire).Render(displayText)
	}

	return style.Foreground(defaultTextColor).Render(displayText)

}

func renderColumnHeader(columns []column, headerWidth int) string {
	var header string
	columnStyle := lipgloss.NewStyle().Foreground(defaultTextColor)

	for i, c := range columns {
		// set the width of the column, subtracting off the column border
		width := c.width - 3

		// the fist column must start with a margin,
		if i == 0 {
			width -= 2 // subtract off the margin
			header += columnStyle.MarginLeft(2).Width(width).Render(c.name)
		} else {
			header += columnStyle.Width(width).Render(c.name)
		}

		// add a column border if not the last column
		if i < len(columns)-1 {
			header += columnStyle.Foreground(surface0).Render(" | ")
		}
	}

	return listHeaderStyle.Width(headerWidth).Render(header)
}
