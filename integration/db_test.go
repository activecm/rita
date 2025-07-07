package integration_test

import (
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
)

func (it *ValidDatasetTestSuite) TestPrimaryKeySize() {
	t := it.T()

	type tableRes struct {
		Table               string  `ch:"table"`
		NumParts            uint64  `ch:"num_parts"`
		TotalMarks          uint64  `ch:"total_marks"`
		AvgMarks            float64 `ch:"avg_marks"`
		TotalPrimaryKeySize uint64  `ch:"total_primary_key_size"`
		CompressionRatio    float64 `ch:"compression_ratio"`
	}

	/* NOTE: !!! PERFORMANCE-CRITICAL TEST !!!
	The purpose of this test is to track the storage efficiency of the valid dataset across continuing development.
	These values should only be increased (CompressionRatio decreased) in order to pass tests IF after deliberate consideration
	has been made on whether or not there is no other performant way of storing the data needed.
	Changes to the schema can cause performance impacts on data insertion and queries.
	*/
	allowedMaximums := map[string]tableRes{
		"big_ol_histogram": {NumParts: 4, TotalMarks: 20, AvgMarks: 10, TotalPrimaryKeySize: 500, CompressionRatio: 0.6},
		"conn":             {NumParts: 2, TotalMarks: 50, AvgMarks: 50, TotalPrimaryKeySize: 6000, CompressionRatio: 0.7},
		"conn_tmp":         {NumParts: 2, TotalMarks: 50, AvgMarks: 50, TotalPrimaryKeySize: 6000, CompressionRatio: 0.7},
		"dns":              {NumParts: 2, TotalMarks: 50, AvgMarks: 50, TotalPrimaryKeySize: 6000, CompressionRatio: 0.6},
		"dns_tmp":          {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 100, CompressionRatio: 0.25},
		"exploded_dns":     {NumParts: 2, TotalMarks: 50, AvgMarks: 50, TotalPrimaryKeySize: 2000, CompressionRatio: 0.4},
		"http":             {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 600, CompressionRatio: 0.7},
		"http_tmp":         {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 600, CompressionRatio: 0.7},
		"http_proto":       {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 1000, CompressionRatio: 0.7},
		"mime_type_uris":   {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 1000, CompressionRatio: 0.7},
		"openconn":         {NumParts: 2, TotalMarks: 60, AvgMarks: 60, TotalPrimaryKeySize: 6000, CompressionRatio: 0.7},
		"openconn_tmp":     {NumParts: 2, TotalMarks: 60, AvgMarks: 60, TotalPrimaryKeySize: 6000, CompressionRatio: 0.7},
		"openhttp":         {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 700, CompressionRatio: 0.7},
		"openhttp_tmp":     {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 700, CompressionRatio: 0.7},
		"openssl":          {NumParts: 2, TotalMarks: 20, AvgMarks: 20, TotalPrimaryKeySize: 2000, CompressionRatio: 0.7},
		"openssl_tmp":      {NumParts: 2, TotalMarks: 20, AvgMarks: 20, TotalPrimaryKeySize: 2000, CompressionRatio: 0.7},
		"pdns":             {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 1000, CompressionRatio: 0.8},
		"pdns_raw":         {NumParts: 2, TotalMarks: 30, AvgMarks: 30, TotalPrimaryKeySize: 4000, CompressionRatio: 0.8},
		"port_info":        {NumParts: 2, TotalMarks: 20, AvgMarks: 20, TotalPrimaryKeySize: 700, CompressionRatio: 0.5},
		"rare_signatures":  {NumParts: 4, TotalMarks: 10, AvgMarks: 5, TotalPrimaryKeySize: 1500, CompressionRatio: 0.35},
		"sniconn_tmp":      {NumParts: 2, TotalMarks: 40, AvgMarks: 40, TotalPrimaryKeySize: 600, CompressionRatio: 0.4},
		"opensniconn_tmp":  {NumParts: 2, TotalMarks: 40, AvgMarks: 40, TotalPrimaryKeySize: 600, CompressionRatio: 0.4},
		"openconnhash_tmp": {NumParts: 2, TotalMarks: 40, AvgMarks: 40, TotalPrimaryKeySize: 2000, CompressionRatio: 0.4},
		"ssl":              {NumParts: 2, TotalMarks: 20, AvgMarks: 20, TotalPrimaryKeySize: 1500, CompressionRatio: 0.7},
		"ssl_tmp":          {NumParts: 2, TotalMarks: 20, AvgMarks: 20, TotalPrimaryKeySize: 1500, CompressionRatio: 0.7},
		"threat_mixtape":   {NumParts: 4, TotalMarks: 10, AvgMarks: 5, TotalPrimaryKeySize: 700, CompressionRatio: 0.7},
		"tls_proto":        {NumParts: 2, TotalMarks: 10, AvgMarks: 10, TotalPrimaryKeySize: 600, CompressionRatio: 0.7},
		"uconn":            {NumParts: 2, TotalMarks: 15, AvgMarks: 15, TotalPrimaryKeySize: 800, CompressionRatio: 0.5},
		"uconn_tmp":        {NumParts: 2, TotalMarks: 60, AvgMarks: 60, TotalPrimaryKeySize: 2000, CompressionRatio: 0.35},
		"udns":             {NumParts: 2, TotalMarks: 50, AvgMarks: 50, TotalPrimaryKeySize: 5000, CompressionRatio: 0.7},
		"usni":             {NumParts: 4, TotalMarks: 10, AvgMarks: 5, TotalPrimaryKeySize: 700, CompressionRatio: 0.5},
	}

	// optimize tables before checking parts
	for table := range allowedMaximums {
		ctx := it.db.QueryParameters(clickhouse.Parameters{
			"table": table,
		})
		err := it.db.Conn.Exec(ctx, `--sql
			OPTIMIZE TABLE {table:Identifier} FINAL
		`)
		require.NoError(t, err)
	}

	var res []tableRes
	ctx := it.db.QueryParameters(clickhouse.Parameters{
		"database": it.db.GetSelectedDB(),
	})
	err := it.db.Conn.Select(ctx, &res, `--sql
			SELECT 
				table, 
				count() AS num_parts, 
				sum(marks) AS total_marks, 
				avg(marks) AS avg_marks, 
				sum(primary_key_bytes_in_memory) AS total_primary_key_size,  
				-- sum(data_uncompressed_bytes) AS uncompressed_size,
                -- sum(data_compressed_bytes) AS compressed_size, 
				-- sum(data_compressed_bytes) / sum(data_uncompressed_bytes) AS compression_ratio 
				1 - (1 / ( sum(data_uncompressed_bytes) / sum(data_compressed_bytes))) AS compression_ratio 
			FROM system.parts
			WHERE database = {database:String} AND active = 1
			GROUP BY table
		`)
	require.NoError(t, err)
	// require.Len(t, res, len(allowedMaximums), "there should be an equal number of tables for the sensor database")

	for _, table := range res {
		currTable := allowedMaximums[table.Table]
		require.LessOrEqual(t, table.NumParts, currTable.NumParts, "%s should have max %d parts, got: %d", table.Table, currTable.NumParts, table.NumParts)
		// only check the number of marks if there is more than one part,
		// since having fewer, larger parts is more efficient because it reduces the overhead
		// of managing many small files and their corresponding marks
		if table.NumParts > 1 {
			require.LessOrEqual(t, table.TotalMarks, currTable.TotalMarks, "%s should have max %d total marks, got: %d", table.Table, currTable.TotalMarks, table.TotalMarks)
			require.LessOrEqual(t, table.AvgMarks, currTable.AvgMarks, "%s should have max %1.1f avg marks, got: %1.1f", table.Table, currTable.AvgMarks, table.AvgMarks)
		}
		require.LessOrEqual(t, table.TotalPrimaryKeySize, currTable.TotalPrimaryKeySize, "%s should have a max total in-memory primary key size of %d, got: %d", table.Table, currTable.TotalPrimaryKeySize, table.TotalPrimaryKeySize)
		require.GreaterOrEqual(t, table.CompressionRatio, currTable.CompressionRatio, "%s should have a min compression ratio of %1.2f, got: %1.2f", table.Table, currTable.CompressionRatio*100, table.CompressionRatio*100)

	}

}
