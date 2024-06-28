package integration_test

import (
	"github.com/stretchr/testify/require"
)

func (it *ValidDatasetTestSuite) TestStrobes() {
	t := it.T()

	var count uint64
	// check that one strobe made it into the mixtape
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM threat_mixtape
		WHERE count >= 86400 AND strobe_score > 0 AND beacon_score = 0 AND beacon_threat_score = 0
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)

	// verify the number of strobes for uconns
	err = it.db.Conn.QueryRow(it.db.GetContext(), `
		SELECT count() FROM (
			SELECT hash, countMerge(count) AS conn_count FROM uconn
			GROUP BY hash
			HAVING conn_count >= 86400
		)
	`).Scan(&count)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)

}
