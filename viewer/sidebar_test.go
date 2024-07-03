package viewer_test

import (
	"github.com/activecm/rita/v5/viewer"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func (s *ViewerTestSuite) TestSidebarScrolling() {
	t := s.T()

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(t, err)

	m.Update(tea.WindowSizeMsg{
		Height: 20, // this must be small enough to trigger scrolling
		Width:  100,
	})

	// get current selected index
	initialSelectedIndex := m.List.Rows.Index()

	initialScroll := m.SideBar.Viewport.YOffset
	// initial scroll position should be zero
	// if it's not, then the contents didn't get set or the dimensions are messed up
	require.EqualValues(t, 0, initialScroll, "initial scroll offset should be 0, got %d", initialScroll)

	// tab key switches focus to the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyTab,
		},
	))

	// down key scrolls the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyDown,
		},
	))

	currentScroll := m.SideBar.Viewport.YOffset
	require.EqualValues(t, currentScroll, initialScroll+1, "scroll offset should be one more than the initial offset after scrolling down, got %d", currentScroll)

	// up key scrolls the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyUp,
		},
	))
	currentScroll = m.SideBar.Viewport.YOffset
	require.EqualValues(t, 0, currentScroll, "current scroll offset should be 0 after scrolling up, got %1.3f", currentScroll)

	// verify that list was not scrolled instead of sidebar by comparing the initially selected and current index
	require.Equal(t, initialSelectedIndex, m.List.Rows.Index())

	// pgdown scrolls a page down the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgDown,
		},
	))

	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgDown,
		},
	))

	require.True(t, m.SideBar.Viewport.AtBottom(), "scroll offset should be at the bottom after paging down twice")

	// pgup scrolls a page up the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgUp,
		},
	))
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgUp,
		},
	))
	require.True(t, m.SideBar.Viewport.AtTop(), "scroll offset should be at the top after paging up twice")

	// switch focus off of sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyTab,
		},
	))

	// down key should scroll the list, not the sidebar
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyDown,
		},
	))

	require.EqualValues(t, initialScroll+1, m.List.Rows.Index(), "list index should have scrolled down one from the initial index (0), got %d", m.List.Rows.Index())
	require.True(t, m.SideBar.Viewport.AtTop(), "scroll offset should still be at the top after scrolling down the list")

}

func (s *ViewerTestSuite) TestSidebarUpdating() {
	t := s.T()

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(t, err)

	m.Update(tea.WindowSizeMsg{Width: 150, Height: 50})

	// get current selected index
	selectedIndex := m.List.Rows.Index()

	// get the items in the list
	items := m.List.Rows.Items()

	// get selected row
	selectedRow, ok := items[selectedIndex].(viewer.Item)
	require.True(t, ok, "casting item to Item should not return an error")

	// check the sidebar data
	require.Equal(t, selectedRow, m.SideBar.Data, "expected sidebar data to be %v, got %v", selectedRow, m.SideBar.Data)

	// scroll down the list 5 times
	for i := 0; i < 5; i++ {
		m.Update(tea.KeyMsg(
			tea.Key{
				Type: tea.KeyDown,
			},
		))
	}

	// get the selected row after scrolling
	selectedRow, ok = items[m.List.Rows.Index()].(viewer.Item)
	require.True(t, ok, "casting item to Item should not return an error")

	// check the sidebar data
	require.Equal(t, selectedRow, m.SideBar.Data, "expected sidebar data to be %v, got %v", selectedRow, m.SideBar.Data)
}
