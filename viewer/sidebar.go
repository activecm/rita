package viewer

import (
	"fmt"
	"strings"
	"time"

	"github.com/activecm/rita/v5/util"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var sideBarStyle = lipgloss.NewStyle()

type modifier struct {
	label string
	value string
	delta float32
}

type sidebarModel struct {
	Viewport       viewport.Model
	Data           *Item
	Height         int
	maxTimestamp   time.Time
	useCurrentTime bool
	ScrollEnabled  bool
}

func NewSidebarModel(maxTS time.Time, useCurrentTime bool, initialData *Item) sidebarModel {
	return sidebarModel{
		Viewport:       viewport.Model{},
		maxTimestamp:   maxTS,
		useCurrentTime: useCurrentTime,
		Data:           initialData,
	}
}

func (m *sidebarModel) Init() tea.Cmd {
	m.Viewport.SetContent(m.getSidebarContents())
	return nil
}

type UpdateItem *Item

func (m *sidebarModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {

	case UpdateItem:

		m.Data = msg
		content := m.getSidebarContents()
		numlines := strings.Count(content, "\n") + 1 + 2

		numToClear := m.Viewport.Height - numlines
		if numToClear > 0 {
			spaces := m.Viewport.Width - 2
			for i := 0; i < numToClear; i++ {
				content += fmt.Sprintf("%*s\n", spaces, "")
			}
		}

		m.Viewport.SetContent(content)

	case tea.WindowSizeMsg:
		cmds = append(cmds, viewport.Sync(m.Viewport))
	}
	return m, tea.Batch(cmds...)
}

func (m *sidebarModel) View() string {
	borderColor := mauve
	if m.ScrollEnabled {
		borderColor = green
	}
	style := sideBarStyle.
		// .Width(m.width)
		// Height(m.Viewport.Height).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor)
	sidebar := style.Render(m.Viewport.View())
	return lipgloss.NewStyle().Render(sidebar)

}

// getSidebarContents gets and formats the data to be displayed in the sidebar
func (m *sidebarModel) getSidebarContents() string {
	if m.Data == nil {
		return lipgloss.NewStyle().Foreground(overlay0).Render("No result found.")
	}

	// get header
	var target string
	headerPadding := 2

	headerLabelStyle := lipgloss.NewStyle().Padding(0, headerPadding).Background(overlay0).Foreground(defaultTextColor).Bold(true)
	headerValueStyle := lipgloss.NewStyle().Padding(0, headerPadding).Background(mauve).Foreground(base).Bold(true)

	// handle c2 over dns threats with just a fqdn as the target
	if m.Data.GetSrc() == "" {
		// dstStyle := lipgloss.NewStyle().Width(m.viewport.Width - (headerPadding * 2))
		fqdnLabel := "FQDN"
		dstStyle := lipgloss.NewStyle().Width(m.Viewport.Width - len(fqdnLabel) - (headerPadding * 4))
		valueStyle := headerValueStyle.Render(Truncate(m.Data.GetDst(), &dstStyle))
		target = lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(fqdnLabel), valueStyle)
		target = lipgloss.NewStyle().MarginBottom(2).Render(target)
	} else {
		// handle connection pair, ip -> ip or ip -> fqdn
		srcLabel := "SRC"
		srcStyle := lipgloss.NewStyle().Width(m.Viewport.Width - len(srcLabel) - (headerPadding * 4))
		dstLabel := "DST"
		dstStyle := lipgloss.NewStyle().Width(m.Viewport.Width - len(dstLabel) - (headerPadding * 4))
		srcValueStyle := headerValueStyle.Render(Truncate(m.Data.GetSrc(), &srcStyle))
		dstValueStyle := headerValueStyle.Render(Truncate(m.Data.GetDst(), &dstStyle))

		src := lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(srcLabel), srcValueStyle)
		dst := lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(dstLabel), dstValueStyle)
		target = lipgloss.JoinVertical(lipgloss.Top, lipgloss.NewStyle().MarginBottom(1).Render(src), dst)
	}
	heading := lipgloss.NewStyle().MarginBottom(1).Render(target)

	// get modifiers
	sectionStyle := lipgloss.NewStyle().
		Foreground(overlay2).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(surface0).
		Width(m.Viewport.Width)
	modifierLabel := sectionStyle.Render("「 Threat Modifiers 」")
	modifiers := m.renderModifiers()

	dataStyle := lipgloss.NewStyle().Foreground(defaultTextColor)

	var connInfoLabel, connCount, bytes string
	// display connection count and bytes for everything except C2 over DNS
	if m.Data.C2OverDNSScore == 0 {
		connInfoLabel = sectionStyle.Render("「 Connection Info 」")

		// get connection count
		connCountStyle := lipgloss.NewStyle().Background(overlay2).Foreground(base).Bold(true).Padding(0, 2)
		connCountHeader := connCountStyle.Render("Connection Count")
		connCount = dataStyle.Render(lipgloss.JoinVertical(lipgloss.Top, connCountHeader, fmt.Sprintf("%d", m.Data.Count)))

		// get total bytes
		bytesHeaderStyle := lipgloss.NewStyle().Background(overlay2).Foreground(base).Bold(true).Padding(0, 2)
		bytesHeader := bytesHeaderStyle.Render("Total Bytes")
		bytes = dataStyle.Render(lipgloss.JoinVertical(lipgloss.Top, bytesHeader, m.Data.TotalBytesFormatted))
	}

	// get port:proto:service
	portProtoService := m.Data.GetPortProtoService()
	// DEBUG SIDEFEED SCROLLING WITH LONG PORT:PROTO:SERVICE
	// var portProtoService []string
	// for i := 0; i < 20; i++ {
	// 	portProtoService = append(portProtoService, fmt.Sprintf("%d : %s : %s", i, "tcp", "http"))
	// }

	ports := ""

	if len(portProtoService) > 0 {
		// create style for header
		portsHeaderStyle := lipgloss.NewStyle().Background(overlay2).Foreground(base).Bold(true).Padding(0, 2).MarginTop(1)

		// render header
		portsHeader := portsHeaderStyle.Render("Port : Proto : Service")
		ports = dataStyle.Render(lipgloss.JoinVertical(lipgloss.Top, portsHeader, strings.Join(portProtoService, "\n")))
	}

	// join contents
	return lipgloss.JoinVertical(lipgloss.Top, heading, modifierLabel, modifiers, connInfoLabel, connCount, bytes, ports)
}

// renderModifiers aggregates and formats the modifiers for the currently selected item
// for rendering in the sidebar
func (m *sidebarModel) renderModifiers() string {
	modifierList := m.getModifiers()

	var modifiers string
	var renderedModifiers []string
	for _, modifier := range modifierList {
		renderedModifier := renderModifier(modifier)
		renderedModifiers = append(renderedModifiers, renderedModifier)
	}
	newlineStyle := lipgloss.NewStyle().PaddingRight(1).BorderForeground(overlay2).Border(lipgloss.NormalBorder(), false, true, false, false)
	linebreakStyle := lipgloss.NewStyle().MarginBottom(1)

	var modifierLines []string
	var currentModifiers string
	for i, mod := range renderedModifiers {
		if i == 0 {
			currentModifiers = newlineStyle.Render(mod)
		} else {

			newMod := lipgloss.JoinHorizontal(lipgloss.Left, currentModifiers, lipgloss.NewStyle().Padding(0, 1).BorderForeground(overlay2).Border(lipgloss.NormalBorder(), false, true, false, false).Render(mod))

			width := lipgloss.Width(newMod)
			if m.Viewport.Width <= width {
				modifierLines = append(modifierLines, lipgloss.NewStyle().Foreground(defaultTextColor).Render(lipgloss.JoinHorizontal(lipgloss.Left, linebreakStyle.Render(currentModifiers))))
				currentModifiers = mod
				if i != len(renderedModifiers)-1 {
					currentModifiers = newlineStyle.Render(mod)
				}
			} else {
				currentModifiers = newMod
			}
		}
	}
	modifierLines = append(modifierLines, linebreakStyle.Render(currentModifiers))
	modifiers = lipgloss.JoinVertical(lipgloss.Top, modifierLines...)

	return modifiers
}

// getModifiers gets all the modifiers for the currently selected item
func (m *sidebarModel) getModifiers() []modifier {
	var modifiers []modifier

	prevalence := "N/A"
	if m.Data.Prevalence > 0 {
		prevalence = fmt.Sprintf("%1.0f%%", m.Data.Prevalence*100)
		// show two decimal points if the prevalence is less than 1% to avoid displaying 0%
		if m.Data.Prevalence < 0.01 {
			prevalence = fmt.Sprintf("%1.2f%%", m.Data.Prevalence*100)
		}
	}
	modifiers = append(modifiers, modifier{label: "Prevalence", value: prevalence, delta: m.Data.PrevalenceScore})

	if m.Data.FirstSeen.Compare(time.Unix(0, 0)) == 1 {
		relativeTime := util.GetRelativeFirstSeenTimestamp(m.useCurrentTime, m.maxTimestamp)
		modifiers = append(modifiers, modifier{label: "First Seen", value: m.Data.GetFirstSeen(relativeTime), delta: m.Data.FirstSeenScore})
	}

	if m.Data.MissingHostCount > 0 {
		modifiers = append(modifiers, modifier{label: "Missing Host Header", value: fmt.Sprintf("Was missing host %dx", m.Data.MissingHostCount), delta: m.Data.MissingHostHeaderScore})
	}

	if m.Data.ThreatIntelDataSizeScore != 0 {
		var label string
		if m.Data.ThreatIntelDataSizeScore > 0 {
			label = "[High Data]"
		} else {
			label = "[Low Data]"
		}
		modifiers = append(modifiers, modifier{label: "Threat Intel " + label, value: m.Data.TotalBytesFormatted, delta: m.Data.ThreatIntelDataSizeScore})
	}

	if m.Data.C2OverDNSDirectConnScore != 0 {
		modifiers = append(modifiers, modifier{label: "No Direct Connections", value: "", delta: 10})
	}

	for _, mod := range m.Data.Modifiers {
		switch mod["modifier_name"] {
		case "rare_signature":
			modifiers = append(modifiers, modifier{label: "Rare Signature", value: mod["modifier_value"], delta: 10})
		case "mime_type_mismatch":
			modifiers = append(modifiers, modifier{label: "MIME Type Mismatch", value: "", delta: 10})
		}
	}

	return modifiers
}

// renderModifier formats and styles a single modifier for rendering
func renderModifier(mod modifier) string {
	var color lipgloss.AdaptiveColor
	switch {
	case mod.delta == 0:
		color = overlay2
	case mod.delta > 0:
		color = red
	case mod.delta < 0:
		color = green
	}

	header := lipgloss.NewStyle().Background(color).Foreground(base).Bold(true).Padding(0, 2).Render(mod.label)

	data := lipgloss.NewStyle().Foreground(defaultTextColor).Render(mod.value)
	modifier := lipgloss.JoinVertical(lipgloss.Top, header, data)
	return modifier
}
