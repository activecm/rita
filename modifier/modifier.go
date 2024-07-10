package modifier

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/activecm/rita/v5/analysis"
	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

const RARE_SIGNATURE_MODIFIER_NAME = "rare_signature"
const MIME_TYPE_MISMATCH_MODIFIER_NAME = "mime_type_mismatch"
const C2_OVER_DNS_DIRECT_CONNECTIONS_MODIFIER_NAME = "c2_over_dns_direct_conns"

// we must batch if we want all of the modifiers pre-scored in one row
// we don't need to if we don't need them all in the same row

type Modifier struct {
	Database        *database.DB
	ImportID        util.FixedString
	Config          *config.Config
	ModifierWorkers int
	minTS           time.Time

	writer *database.BulkWriter
}

type ThreatModifier struct {
	AnalyzedAt    int64            `ch:"analyzed_at"`
	ImportID      util.FixedString `ch:"import_id"`
	Hash          util.FixedString `ch:"hash"`
	Src           net.IP           `ch:"src"`
	Dst           net.IP           `ch:"dst"`
	SrcNUID       uuid.UUID        `ch:"src_nuid"`
	DstNUID       uuid.UUID        `ch:"dst_nuid"`
	FQDN          string           `ch:"fqdn"`
	LastSeen      time.Time        `ch:"last_seen"`
	ModifierName  string           `ch:"modifier_name"`
	ModifierScore float32          `ch:"modifier_score"`
}

func NewModifier(db *database.DB, cfg *config.Config, importID util.FixedString, minTS time.Time, maxTS time.Time) (*Modifier, error) {
	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)

	return &Modifier{
		Database:        db,
		ImportID:        importID,
		Config:          cfg,
		ModifierWorkers: 1,
		minTS:           minTS,
		writer:          database.NewBulkWriter(db, cfg, 1, db.GetSelectedDB(), "threat_mixtape", "INSERT INTO {database:Identifier}.threat_mixtape", limiter, false),
	}, nil
}

func (modifier *Modifier) Modify() error {
	logger := logger.GetLogger()

	// log the start time of the modifier detection
	start := time.Now()
	logger.Debug().Msg("Starting Modifier")

	modifier.writer.Start(0)
	// create an error group to manage the modifier threads
	modifierErrGroup, ctx := errgroup.WithContext(context.Background())

	// kick off individual modifier threads
	modifierErrGroup.Go(func() error {
		err := modifier.detectRareSignature(ctx)
		return err
	})

	modifierErrGroup.Go(func() error {
		err := modifier.detectMIMETypeMismatch(ctx)
		return err
	})

	// wait for all modifier threads to finish
	if err := modifierErrGroup.Wait(); err != nil {
		logger.Fatal().Err(err).Msg("could not perform modifier detection")
		return err
	}

	modifier.writer.Close()
	// log the end time of the modifer detection
	end := time.Now()
	diff := time.Since(start)
	logger.Info().Time("modification_began", start).Time("modification_finished", end).Str("elapsed_time", diff.String()).Msg("Finished Modification! 🎉")

	return nil
}

func (modifier *Modifier) detectRareSignature(ctx context.Context) error {
	logger := logger.GetLogger()
	logger.Debug().Msg("Starting detection of rare signatures...")
	chCtx := modifier.Database.QueryParameters(clickhouse.Parameters{
		"min_ts":    fmt.Sprintf("%d", modifier.minTS.UTC().Unix()),
		"import_id": modifier.ImportID.Hex(),
	})

	rows, err := modifier.Database.Conn.Query(chCtx, `--sql
	WITH rare_sig_modifiers AS (
		SELECT src, src_nuid, dst, dst_nuid, fqdn, signature as modifier_value, x.times_used_dst as times_used_dst, x.times_used_fqdn as times_used_fqdn
		FROM rare_signatures rs 
		SEMI JOIN (
			SELECT src, src_nuid, signature, uniqExactMerge(times_used_dst) as times_used_dst, uniqExactMerge(times_used_fqdn) as times_used_fqdn 
			FROM rare_signatures
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64})) AND signature != ''
			GROUP BY src, src_nuid, signature
			HAVING times_used_fqdn = 1 OR  times_used_dst = 1
		) x ON rs.src = x.src AND rs.src_nuid = x.src_nuid AND rs.signature = x.signature
		WHERE if(fqdn != '', times_used_fqdn = 1, times_used_dst = 1)
	)
	SELECT hash, src, src_nuid, dst, dst_nuid, fqdn, r.modifier_value as modifier_value, last_seen, toFloat32(if(length(fqdn) > 0, times_used_fqdn, times_used_dst)) as modifier_score
	FROM threat_mixtape t 
	SEMI JOIN rare_sig_modifiers r USING src, src_nuid, dst, dst_nuid, fqdn
	WHERE modifier_name = '' -- join only on non-modifier rows to avoid duplicating results
	AND t.import_id = unhex({import_id:String}) -- join only on the results for this import
	`)

	if err != nil {
		return err
	}

	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling rare signature modifier query")
			rows.Close()
			return ctx.Err()
		default:
			var res analysis.ThreatMixtape
			if err := rows.ScanStruct(&res); err != nil {
				// return error and cancel all uconn analysis
				return fmt.Errorf("could not read entry for rare signature modifier detection: %w", err)
			}

			res.AnalyzedAt = modifier.Database.ImportStartedAt.Truncate(time.Microsecond)

			// set the first and last timestamps to the beginning of the Unix epoch because ClickHouse is being
			// finicky with these fields not being directly set
			beginningEpoch := time.Unix(0, 0)
			res.FirstSeenHistorical = beginningEpoch
			// res.LastSeen = beginningEpoch

			res.ImportID = modifier.ImportID
			res.ModifierName = RARE_SIGNATURE_MODIFIER_NAME
			res.ModifierScore = modifier.Config.Modifiers.RareSignatureScoreIncrease
			// send the unique sni connections to the uconn analysis channel
			modifier.writer.WriteChannel <- &res
		}
	}
	rows.Close()

	return nil
}

func (modifier *Modifier) detectMIMETypeMismatch(ctx context.Context) error {
	logger := logger.GetLogger()
	logger.Debug().Msg("Starting detection of MIME type/URI mismatch...")
	chCtx := modifier.Database.QueryParameters(clickhouse.Parameters{
		"min_ts":    fmt.Sprintf("%d", modifier.minTS.UTC().Unix()),
		"import_id": modifier.ImportID.Hex(),
	})

	rows, err := modifier.Database.Conn.Query(chCtx, `--sql
		WITH totaled_mimeuri AS (
			SELECT hash, countMerge(mismatch_count) as mismatch_count
			FROM mime_type_uris
			WHERE hour >= toStartOfHour(fromUnixTimestamp({min_ts:Int64})) 
			GROUP BY hash
		)
		SELECT hash, src, src_nuid, dst, dst_nuid, fqdn, last_seen, toString(m.mismatch_count) as modifier_value 
		FROM threat_mixtape t
		INNER JOIN totaled_mimeuri m USING hash
		WHERE t.import_id = unhex({import_id:String})
	`)

	if err != nil {
		return err
	}

	for rows.Next() {
		select {
		// abort this function if the context was cancelled
		case <-ctx.Done():
			logger.Warn().Msg("cancelling MIME type/URI mismatch modifier query")
			rows.Close()
			return ctx.Err()
		default:
			// fmt.Println("hi")
			var res analysis.ThreatMixtape
			if err := rows.ScanStruct(&res); err != nil {
				// return error and cancel all uconn analysis
				return fmt.Errorf("could not read entry for MIME type/URI mismatch modifier detection: %w", err)
			}

			// set analyzed at time to the time the import was started
			res.AnalyzedAt = modifier.Database.ImportStartedAt.Truncate(time.Microsecond)

			// set the first seen timestamp to the beginning of the Unix epoch because ClickHouse is being
			// finicky with these fields not being directly set
			res.FirstSeenHistorical = time.Unix(0, 0)

			res.ImportID = modifier.ImportID
			res.ModifierName = MIME_TYPE_MISMATCH_MODIFIER_NAME
			res.ModifierScore = modifier.Config.Modifiers.MIMETypeMismatchScoreIncrease

			// send the modifier to the writer
			modifier.writer.WriteChannel <- &res
		}
	}
	rows.Close()

	return nil
}

// RESULTS

// SELECT max(last_seen) as most_recent, hash, src, dst, fqdn, beacon_score, long_conn_score, strobe_score, sum(modifier_score) as modifier_delta
// FROM chickenstrip4.threat_mixtape
// GROUP BY hash, src, dst, fqdn, beacon_score, long_conn_score, strobe_score
// HAVING last_seen = most_recent

// SELECT src, dst, subdomain FROM chickenstip4.uconn u
// INNER JOIN chickenstip4.pdns p ON u.dst = p.resolved_ip

// // server ips (src that made dns query to tld)
// 10.55.100.10

// //  "direct connections"
// 10.55.100.10
// 192.14.54.2

// if no ips other than the ones in server ips are in direct connections, we boost score
