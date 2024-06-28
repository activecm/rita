package progressbar

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	padding  = 2
	maxWidth = 80
)

// type ProgressMsg float64
type ProgressMsg struct {
	ID      int
	Percent float64
}

type ProgressSpinnerMsg int

type ProgressBar struct {
	bar     progress.Model
	name    string
	id      int
	percent float64
}

type Spinner struct {
	spinner spinner.Model
	id      int
	name    string
	done    bool
}

type ProgressModel struct {
	ProgressBars     []*ProgressBar
	Spinners         []Spinner
	doneCount        int
	spinnerDoneCount int
	ctx              context.Context
}

func (m ProgressModel) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd()}
	for i := range m.Spinners {
		cmds = append(cmds, m.Spinners[i].spinner.Tick)
	}
	return tea.Batch(cmds...)
}

func NewBar(name string, id int, bar progress.Model) *ProgressBar {
	return &ProgressBar{name: name, id: id, bar: bar}
}

func NewSpinner(name string, id int) Spinner {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return Spinner{name: name, id: id, spinner: s}
}

func New(ctx context.Context, bars []*ProgressBar, spinners []Spinner) *tea.Program {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return tea.NewProgram(ProgressModel{
		ProgressBars: bars,
		Spinners:     spinners,
		ctx:          ctx,
	})
}

type tickMsg string

// tickCmd sends out a tickMsg every tick so that the program can be closed if context is done
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*1, func(_ time.Time) tea.Msg {
		return tickMsg("")
	})
}

func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		select {
		// quit the bubble tea program if the context was cancelled
		case <-m.ctx.Done():
			return m, tea.Quit
		default:
			return m, tickCmd()
		}

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		return m, nil
	case tea.WindowSizeMsg:
		for _, prog := range m.ProgressBars {
			prog.bar.Width = msg.Width - padding*2 - 4
			if prog.bar.Width > maxWidth {
				prog.bar.Width = maxWidth
			}
		}
		return m, nil
	case ProgressSpinnerMsg:
		m.Spinners[msg].done = true
		m.spinnerDoneCount++
		if m.doneCount == len(m.ProgressBars) && m.spinnerDoneCount == len(m.Spinners) {
			return m, tea.Quit
		}
		return m, nil
	case ProgressMsg:
		doneCount := 0
		for _, prog := range m.ProgressBars {
			// if the progress bar's id matches the message's id, update the bar's percent
			if prog.id == msg.ID {
				prog.percent = msg.Percent
			}
			// check if the progress is 100% for each bar, regardless of ID
			if prog.percent == 1.0 {
				doneCount++
			}
		}
		// check that all bars are complete before exiting the progress program
		if doneCount == len(m.ProgressBars) && m.spinnerDoneCount == len(m.Spinners) {
			return m, tea.Quit
		}
		m.doneCount = doneCount
		return m, nil
	case spinner.TickMsg:
		for i := range m.Spinners {
			if m.Spinners[i].spinner.ID() == msg.ID {
				var cmd tea.Cmd
				m.Spinners[i].spinner, cmd = m.Spinners[i].spinner.Update(msg)
				return m, cmd
			}
		}
		return m, nil
	default:
		return m, nil
	}

}

func (m ProgressModel) View() string {
	pad := strings.Repeat(" ", padding)
	render := ""

	for _, prog := range m.ProgressBars {
		render += "\n" + prog.name
		if prog.percent == 1.0 {
			render += " 🎉"
		}
		render += pad + prog.bar.ViewAs(prog.percent) + "\n\n"
	}
	for i := range m.Spinners {
		spinnerTxt := m.Spinners[i].spinner.View()
		if m.Spinners[i].done {
			spinnerTxt = "✅"
		}
		render += fmt.Sprintf("\n%s %s\n\n", spinnerTxt, m.Spinners[i].name)
	}
	return render
}
