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
func (m *sidebarModel) Update(_ tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m *sidebarModel) View() string {
	m.Viewport.SetContent(m.getSidebarContents())
	borderColor := mauve
	if m.ScrollEnabled {
		borderColor = green
	}
	style := sideBarStyle.
		// .Width(m.width).Height(m.height).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor)

	return style.Render(m.Viewport.View())
}

func (m *sidebarModel) getSidebarContents() string {

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

		target = lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(fqdnLabel), headerValueStyle.Render(Truncate(m.Data.GetDst(), &dstStyle)))
		target = lipgloss.NewStyle().MarginBottom(2).Render(target)
	} else {
		// handle connection pair, ip -> ip or ip -> fqdn
		srcLabel := "SRC"
		srcStyle := lipgloss.NewStyle().Width(m.Viewport.Width - len(srcLabel) - (headerPadding * 4))
		dstLabel := "DST"
		dstStyle := lipgloss.NewStyle().Width(m.Viewport.Width - len(dstLabel) - (headerPadding * 4))
		// - 6 - len(m.data.GetSrc())
		// dstStyle := lipgloss.NewStyle().Width(dstWidth)
		src := lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(srcLabel), headerValueStyle.Render(Truncate(m.Data.GetSrc(), &srcStyle)))
		dst := lipgloss.JoinHorizontal(lipgloss.Left, headerLabelStyle.Render(dstLabel), headerValueStyle.Render(Truncate(m.Data.GetDst(), &dstStyle)))
		target = lipgloss.JoinVertical(lipgloss.Top, lipgloss.NewStyle().MarginBottom(1).Render(src), dst)
	}
	heading := lipgloss.NewStyle().
		// PaddingLeft(headerPadding).
		MarginBottom(1).Render(target)

	// get modifiers
	sectionStyle := lipgloss.NewStyle().
		Foreground(overlay2).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(surface0).
		Width(m.Viewport.Width)
	modifierLabel := sectionStyle.Render("「 Threat Modifiers 」")
	modifiers := m.renderModifiers()

	connInfoLabel := sectionStyle.Render("「 Connection Info 」")

	// get connection count
	connCountStyle := lipgloss.NewStyle().Background(overlay2).Foreground(base).Bold(true).Padding(0, 2)
	connCountHeader := connCountStyle.Render("Connection Count")
	connCount := lipgloss.JoinVertical(lipgloss.Top, connCountHeader, fmt.Sprintf("%d", m.Data.Count))

	// get total bytes
	bytesHeaderStyle := lipgloss.NewStyle().Background(overlay2).Foreground(base).Bold(true).Padding(0, 2)
	bytesHeader := bytesHeaderStyle.Render("Total Bytes")
	bytes := lipgloss.JoinVertical(lipgloss.Top, bytesHeader, m.Data.TotalBytesFormatted)

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
		ports = lipgloss.JoinVertical(lipgloss.Top, portsHeader, strings.Join(portProtoService, "\n"))

		// calculate the number of lines available for port data
		// remainingLines := m.viewport.Height - (lipgloss.Height(heading) + lipgloss.Height(modifiers) + lipgloss.Height(modifierLabel) + lipgloss.Height(connInfoLabel) + lipgloss.Height(bytes) + lipgloss.Height(connCount))
		// ports = renderPorts(portProtoService, m.viewport.Width, remainingLines)

	}

	// join contents
	return lipgloss.JoinVertical(lipgloss.Top, heading, modifierLabel, modifiers, connInfoLabel, connCount, bytes, ports)
}

func (m *sidebarModel) renderModifiers() string {
	modifierList := m.getModifiers()
	// panic(modifierList)

	var modifiers string
	var renderedModifiers []string
	for _, modifier := range modifierList {
		renderedModifier := renderModifier(modifier)
		// if i > 0 {
		// 	renderedModifier = lipgloss.NewStyle().MarginLeft(1).Render(renderedModifier)
		// }
		renderedModifiers = append(renderedModifiers, renderedModifier)
	}
	newlineStyle := lipgloss.NewStyle().PaddingRight(1).BorderForeground(overlay2).Border(lipgloss.NormalBorder(), false, true, false, false)
	linebreakStyle := lipgloss.NewStyle().MarginBottom(1)
	// if len(renderedModifiers) > 2 {

	var modifierLines []string
	// lastUsedIndex := 0
	var currentModifiers string
	for i, mod := range renderedModifiers {
		if i == 0 {
			currentModifiers = newlineStyle.Render(mod)
		} else {
			// modifier = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, true, false, false).Padding(0, 2, 0, 0).Render(modifier)

			newMod := lipgloss.JoinHorizontal(lipgloss.Left, currentModifiers, lipgloss.NewStyle().Padding(0, 1).BorderForeground(overlay2).Border(lipgloss.NormalBorder(), false, true, false, false).Render(mod))
			// panic(newMod)

			width := lipgloss.Width(newMod)
			if m.Viewport.Width <= width {
				modifierLines = append(modifierLines, lipgloss.JoinHorizontal(lipgloss.Left, linebreakStyle.Render(currentModifiers)))
				// lastUsedIndex = i
				currentModifiers = mod
				if i != len(renderedModifiers)-1 {
					currentModifiers = newlineStyle.Render(mod)
				}
			} else {
				currentModifiers = newMod
				// if i != len(renderedModifiers)-1 {
				// 	currentModifiers = newlineStyle.Render(newMod)
				// }
			}
		}
		// modifiers += mod
	}
	modifierLines = append(modifierLines, linebreakStyle.Render(currentModifiers))
	// panic(modifierLines)
	modifiers = lipgloss.JoinVertical(lipgloss.Top, modifierLines...)
	// modifiers = lipgloss.NewStyle().MarginBottom(1).PaddingBottom(1).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(surface0).Render(modifiers)

	// }
	return modifiers
}

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
