package viewer

import (
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type footerModel struct {
	spinner  spinner.Model
	loading  bool
	dbName   string
	width    int
	flashRed bool
	flashing bool
	ErrMsg   string
}

type FooterFlash string

func NewFooterModel(dbName string) footerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(red)
	return footerModel{spinner: s, dbName: dbName}
}

func (m *footerModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func tickCmd(msg string) tea.Cmd {
	ms := time.Millisecond * 100
	if msg == "reset" {
		ms = time.Millisecond * 700
	}
	return tea.Tick(ms, func(_ time.Time) tea.Msg {
		return FooterFlash(msg)
	})
}

func (m *footerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case StillLoadingResults:
		// don't allow the flashing routing to start again if it's already began
		// it will look ugly if multiple flashes are running
		if !m.flashing {
			// immediately mark this as flashing
			m.flashing = true
			m.flashRed = true
			// toggle to normal color after timeout
			return m, tickCmd("normal")
		}
		return m, nil
	case FooterFlash:
		switch msg {
		case "normal":
			m.flashRed = false
			// toggle to red after timeout
			return m, tickCmd("red")
		case "red":
			m.flashRed = true
			// toggle to normal color after timeout
			return m, tickCmd("debounce")
		case "debounce":
			m.flashRed = false
			// toggle the resetting of the flashing flag
			// after a longer timeout so that the bar doesn't flash like crazy
			// if the user keeps pressing next page
			return m, tickCmd("reset")
		case "reset":
			m.flashing = false
		}

		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		default:
			return m, nil
		}

	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

func (m *footerModel) View() string {
	barColor := surface0
	if m.ErrMsg != "" || m.flashRed {
		barColor = pink
	}
	msg := "Loading results"
	if m.ErrMsg != "" {
		msg = m.ErrMsg
	}
	dbFooter := mainStyle.Copy().Margin(0, 0, 0, 0).Padding(0, 2).Background(lavender).Foreground(base).AlignVertical(lipgloss.Bottom).Bold(true).Render("Database")
	spinnerWidth := m.width - 12 - 10 - 2 - len(m.dbName) - len(msg) - 1
	middleBarStyle := mainStyle.Copy().Background(barColor).Foreground(defaultTextColor)
	dbFooter += middleBarStyle.PaddingLeft(1).Render(m.dbName)
	if m.loading {
		dbFooter += middleBarStyle.Copy().Width(spinnerWidth).AlignHorizontal(lipgloss.Right).Render(m.spinner.View())
		dbFooter += middleBarStyle.PaddingRight(1).Render(msg)
	} else {
		dbFooter += middleBarStyle.Copy().Width(spinnerWidth + len(msg) + 2).Render()
	}
	dbFooter += mainStyle.Copy().Background(overlay2).Padding(0, 2).Render("? help")
	return dbFooter

}
