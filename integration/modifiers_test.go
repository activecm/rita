package integration_test

import "github.com/stretchr/testify/require"

func (it *ValidDatasetTestSuite) TestRareSignaturesModifier() {
	t := it.T()
	var count uint64
	err := it.db.Conn.QueryRow(it.db.GetContext(), `
		WITH mixtape AS (
			SELECT DISTINCT src, src_nuid, dst, dst_nuid, fqdn, modifier_value 
			FROM threat_mixtape 
			WHERE modifier_name = 'rare_signature'
		), rare_sigs AS (
			SELECT src, src_nuid, signature, uniqExactMerge(times_used_dst) as times_used_dst, uniqExactMerge(times_used_fqdn) as times_used_fqdn
			FROM rare_signatures
			GROUP BY src, src_nuid, signature
			HAVING times_used_dst = 1 OR times_used_fqdn = 1
		)
		SELECT count() FROM mixtape m
		LEFT JOIN rare_sigs r ON r.src = m.src AND m.src_nuid = r.src_nuid AND m.modifier_value = r.signature
		WHERE (fqdn != '' AND times_used_fqdn != 1) OR (fqdn = '' AND times_used_dst != 1)
	`).Scan(&count)
	require.NoError(t, err)
	require.Zero(t, count, "all rare signature entries in the mixtape should actually be used only once according to rare_signatures table")

}

func (it *ValidDatasetTestSuite) TestC2OverDNSDirectConnsModifier() {
	t := it.T()
	var count uint64
	rows, err := it.db.Conn.Query(it.db.GetContext(), `
		SELECT DISTINCT fqdn, c2_over_dns_direct_conn_score 
		FROM threat_mixtape 
		WHERE beacon_type = 'dns'
	`)
	require.NoError(t, err)
	require.Positive(t, it.cfg.Modifiers.C2OverDNSDirectConnScoreIncrease)

	for rows.Next() {
		var fqdn string
		var score float32
		require.NoError(t, rows.Scan(&fqdn, &score))

		if fqdn == "r-1x.com" || fqdn == "amazonaws.com" {
			require.EqualValues(t, it.cfg.Modifiers.C2OverDNSDirectConnScoreIncrease, score, "score should match modifier increase value: %1.6f, got: %1.6f", it.cfg.Modifiers.C2OverDNSDirectConnScoreIncrease, score)
		} else {
			require.Equal(t, 0, score, "domains without a modifier should have a score of zero, got: %1.6f", score)
		}
	}
	require.Zero(t, count, "all rare signature entries in the mixtape should actually be used only once according to rare_signatures table")

}
