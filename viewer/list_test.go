package viewer_test

import (
	"github.com/activecm/rita/v5/viewer"
	"github.com/stretchr/testify/require"

	tea "github.com/charmbracelet/bubbletea"
)

func (s *ViewerTestSuite) TestListScrolling() {
	t := s.T()

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(t, err)

	// get current selected index
	initialSelectedIndex := m.List.Rows.Index()

	// use down key to scroll the list down five times
	for i := 0; i < 5; i++ {
		m.Update(tea.KeyMsg(
			tea.Key{
				Type: tea.KeyDown,
			},
		))
	}

	// verify that the list was scrolled down five times from the initially selected index
	require.Equal(t, initialSelectedIndex+5, m.List.Rows.Index())

	// use up key to scroll the list up three times
	for i := 0; i < 3; i++ {
		m.Update(tea.KeyMsg(
			tea.Key{
				Type: tea.KeyUp,
			},
		))
	}

	// verify that the list was scrolled up 3 times, resulting in an index of 2 away from the initial index
	require.Equal(t, initialSelectedIndex+2, m.List.Rows.Index())

}

func (s *ViewerTestSuite) TestListPaging() {
	t := s.T()

	// create new ui model
	m, err := viewer.NewModel(s.maxTimestamp, s.minTimestamp, s.useCurrentTime, s.db)
	require.NoError(t, err)

	// get current page
	initialPage := m.List.Rows.Paginator.Page

	// select the 5th row in the list to ensure that the cursor is kept on the same row while paging
	cursor := 5
	m.List.Rows.Select(cursor)

	// get current selected index
	initialSelectedIndex := m.List.Rows.Index()

	// use page down key to page down 5 pages in the list
	for i := 0; i < 5; i++ {
		m.Update(tea.KeyMsg(
			tea.Key{
				Type: tea.KeyPgDown,
			},
		))
	}

	// verify that the list was paged down five times from the initial page
	require.Equal(t, initialPage+5, m.List.Rows.Paginator.Page, "after paging down 5 times, expected page to be %d, got %d", initialPage+5, m.List.Rows.Paginator.Page)

	// verify that the selected index was updated accordingly
	require.Equal(t, initialSelectedIndex+(m.List.Rows.Paginator.PerPage*5), m.List.Rows.Index(), "after paging down 5 times, expected selected index to be %d, got %d", initialSelectedIndex+(m.List.Rows.Paginator.PerPage*5), m.List.Rows.Index())

	// verify that the cursor is still on the 5th row
	require.Equal(t, cursor, m.List.Rows.Cursor(), "after paging down 5 times, expected cursor to remain as %d, got %d", cursor, m.List.Rows.Cursor())

	// use page up key to scroll the list up 3 pages
	for i := 0; i < 3; i++ {
		m.Update(
			tea.KeyMsg{
				Type: tea.KeyPgUp,
			},
		)
	}

	// verify that the list was paged up 3 times, resulting in 2 pages away from the initial page (since we paged down 5 times first)
	require.Equal(t, initialPage+2, m.List.Rows.Paginator.Page, "after paging up 3 times, expected page to be %d, got %d", initialPage+2, m.List.Rows.Paginator.Page)

	// verify that the selected index was updated accordingly
	require.Equal(t, initialSelectedIndex+(m.List.Rows.Paginator.PerPage*2), m.List.Rows.Index(), "after paging up 3 times, expected index to be %d, got %d", initialSelectedIndex+(m.List.Rows.Paginator.PerPage*2), m.List.Rows.Index())

	// verify that the cursor is still on the correct row
	require.Equal(t, cursor, m.List.Rows.Cursor(), "after paging up 3 times, expected cursor to remain as %d, got %d", cursor, m.List.Rows.Cursor())

	// use home key to scroll to the start of the list
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyHome,
		},
	))

	// verify that the list was paged to the start
	require.Equal(t, 0, m.List.Rows.Paginator.Page, "after paging to the start, expected page to be %d, got %d", 0, m.List.Rows.Paginator.Page)

	// verify that the selected index was updated accordingly
	require.Equal(t, initialSelectedIndex, m.List.Rows.Index(), "after paging to the start, expected index to be %d, got %d", initialSelectedIndex, m.List.Rows.Index())

	// verify that the cursor is still on the correct row
	require.Equal(t, cursor, m.List.Rows.Cursor(), "after paging to the start, expected cursor to remain as %d, got %d", cursor, m.List.Rows.Cursor())

	// use page end key to scroll to the end of the list
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyEnd,
		},
	))

	// verify that the list was paged to the end
	require.Equal(t, m.List.Rows.Paginator.TotalPages-1, m.List.Rows.Paginator.Page, "after paging to the end, expected page to be %d, got %d", m.List.Rows.Paginator.TotalPages-1, m.List.Rows.Paginator.Page)

	// verify that the selected index was updated accordingly (since the last page may have fewer items than the cursor index, the selected index should be min(cursor, items on last page - 1 ))
	endCursor := min(cursor, m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items()))-1)
	endIndex := (m.List.Rows.Paginator.Page * m.List.Rows.Paginator.PerPage) + endCursor
	require.Equal(t, endIndex, m.List.Rows.Index(), "after paging to the end, expected selected index to be %d, got %d", endIndex, m.List.Rows.Index())

	// verify that the cursor was updated to the correct spot
	require.Equal(t, endCursor, m.List.Rows.Cursor(), "after paging to the end, expected cursor to be %d, got %d", endCursor, m.List.Rows.Cursor())

	// page up one page (to the second-to-last page)
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgUp,
		},
	))

	// set the cursor down to the bottom row of the second-to-last page to ensure that the selected row is greater than the number of items on the last page we will page to
	m.List.Rows.Select((m.List.Rows.Paginator.Page * m.List.Rows.Paginator.PerPage) + (m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())) - 1))

	// page down one page (back to last page)
	m.Update(tea.KeyMsg(
		tea.Key{
			Type: tea.KeyPgDown,
		},
	))

	// // verify that the list was paged up to the last page
	require.Equal(t, m.List.Rows.Paginator.TotalPages-1, m.List.Rows.Paginator.Page, "after paging up to the last page, expected page to be %d, got %d", m.List.Rows.Paginator.TotalPages-1, m.List.Rows.Paginator.Page)

	// verify that the selected index was updated accordingly to the last item on the last page
	require.Equal(t, endIndex, m.List.Rows.Index(), "after paging up to the last page, expected selected index to be %d, got %d", endIndex, m.List.Rows.Index())

	// verify that the cursor was updated to the correct spot
	require.Equal(t, endCursor, m.List.Rows.Cursor(), "after paging up to the last page, expected cursor to be %d, got %d", endCursor, m.List.Rows.Cursor())

	// fmt.Printf("page: %d\n", m.List.Rows.Paginator.Page)
	// fmt.Printf("initialSelectedIndex: %d\n", initialSelectedIndex)
	// fmt.Printf("actual index: %d\n", m.List.Rows.Index())
	// fmt.Printf("perPage: %d\n", m.List.Rows.Paginator.PerPage)
	// fmt.Printf("items on page: %d\n", m.List.Rows.Paginator.ItemsOnPage(len(m.List.Rows.Items())))
	// fmt.Printf("cursor: %d\n", m.List.Rows.Cursor())

}
