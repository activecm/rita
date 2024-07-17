package database

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/activecm/rita/v5/config"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/util"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
)

// threatIntelFeed represents a threat intel feed source from config
type threatIntelFeed struct {
	LastModified time.Time
	Online       bool
	Existing     bool
}

// threatIntelFeedRecord represents a record in the threat_intel_feeds table
type threatIntelFeedRecord struct {
	Hash               util.FixedString `ch:"hash"`
	Path               string           `ch:"path"`
	Online             bool             `ch:"online"`
	LastModifiedOnDisk time.Time        `ch:"last_modified_on_disk"` // time the custom feed file was last modified on the file system
	LastModified       time.Time        `ch:"last_modified"`         // used for troubleshooting/seeing the last time it was updated in DB
}

// threatIntelFeedEntry represents a record in the threat_intel table
type threatIntelFeedEntry struct {
	Hash util.FixedString `ch:"hash"`
	IP   netip.Addr       `ch:"ip"`
	FQDN string           `ch:"fqdn"`
}

// createThreatIntelTables creates the threat intel tables in the metadatabase
func (server *ServerConn) createThreatIntelTables() error {

	// create table to store threat intel entries
	err := server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.threat_intel (
		hash FixedString(16),
		ip IPv6,
		fqdn String,
	) ENGINE = MergeTree()
	PRIMARY KEY (hash, fqdn, ip)
	`)
	if err != nil {
		return err
	}

	// create table to store threat intel feeds and their last modified date
	err = server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.threat_intel_feeds(
		hash FixedString(16),
		path String,
		online Bool,
		last_modified_on_disk DateTime('UTC'),
		last_modified DateTime('UTC'),
	) ENGINE = ReplacingMergeTree(last_modified)
	ORDER BY (hash, path)
	`)
	if err != nil {
		return err
	}

	return nil
}

// syncThreatIntelFeedsFromConfig updates the threat intel feeds in the metadatabase based on the config
func (server *ServerConn) syncThreatIntelFeedsFromConfig(afs afero.Fs, cfg *config.Config) error {
	logger := zlog.GetLogger()

	// get the list of threat intel feeds from the config
	feeds, err := getThreatIntelFeeds(afs, cfg)
	if err != nil {
		return err
	}

	// get list of all feeds from the metadatabase
	rows, err := server.Conn.Query(server.ctx, `
		SELECT hash, path, online, most_recent_last_modified AS last_modified, last_modified_on_disk FROM (
			SELECT  hash, path, online, max(last_modified) AS most_recent_last_modified, argMax(last_modified_on_disk, last_modified) AS last_modified_on_disk 
			FROM metadatabase.threat_intel_feeds
			GROUP BY hash, path, online
		)
	`)
	if err != nil {
		return err
	}

	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)

	// create a channel to write feed entries to the database
	writer := NewBulkWriter(server, cfg, 1, "metadatabase", "threat_intel", "INSERT INTO metadatabase.threat_intel", limiter, false)
	writer.Start(0)

	// iterate over each existing feed in the database
	for rows.Next() {

		var entry threatIntelFeedRecord

		err = rows.ScanStruct(&entry)
		if err != nil {
			return err
		}

		// check if feed was removed from the config
		feedRemovedFromConfig := false
		if res, ok := feeds[entry.Path]; !ok {
			feedRemovedFromConfig = true
		} else {
			// mark feed as existing (record exists in the database)
			res.Existing = true
			feeds[entry.Path] = res
		}

		var feed io.ReadCloser

		// process the feed as needed based on its status
		switch {
		// if feed was removed from the config, remove it from the database
		case feedRemovedFromConfig:
			logger.Warn().Str("feed_path", entry.Path).Msg("[THREAT INTEL] Removing threat intel feed because it is no longer listed in the config")
			// remove feed from database
			if err = server.removeFeed(entry.Hash); err != nil {
				return err
			}
			// skip to next feed
			continue

		// if feed has no last modified date on disk, update as online feed
		case entry.Online:
			logger.Info().Str("feed_url", entry.Path).Msg("[THREAT INTEL] Updating online feed...")

			// download the feed
			feed, err = getOnlineFeed(server.GetContext(), entry.Path)
			if err != nil {
				return err
			}

		// if feed has has an oudated last modified date, update as custom feed
		case !entry.LastModifiedOnDisk.Equal(feeds[entry.Path].LastModified):
			logger.Info().Str("feed_path", entry.Path).Msg("[THREAT INTEL] Updating custom feed because it has been modified...")
			// open the feed file
			feed, err = getCustomFeed(entry.Path)
			if err != nil {
				return err
			}

		// feed is up to date, skip ahead to next feed
		default:
			continue

		}

		// update the feed record in the database
		if err = server.updateFeed(&entry, feeds[entry.Path].LastModified, feed, writer.WriteChannel); err != nil {
			return err
		}

	}
	// iterate over each feed in the config that was not in the database
	for path := range feeds {
		entry := feeds[path]
		if !entry.Existing {
			var feed io.ReadCloser
			if entry.Online {
				// download the feed
				feed, err = getOnlineFeed(server.GetContext(), path)
				if err != nil {
					return err
				}
				logger.Info().Str("feed_url", path).Msg("[THREAT INTEL] Adding new online feed...")

			} else {
				// open the feed file
				feed, err = getCustomFeed(path)
				if err != nil {
					return err
				}
				logger.Info().Str("feed_path", path).Msg("[THREAT INTEL] Adding new custom feed...")

			}

			// add the new feed to the database
			if err = server.addNewFeed(path, &entry, feed, writer.WriteChannel); err != nil {
				return err
			}
		}
	}
	writer.Close()
	return nil
}

// fs := afero.NewOsFs()
// getThreatIntelFeeds parses the threat intel sources from the config file into a feed map
func getThreatIntelFeeds(afs afero.Fs, cfg *config.Config) (map[string]threatIntelFeed, error) {
	feeds := make(map[string]threatIntelFeed)
	// add custom feed sources
	if err := getCustomFeedsList(afs, feeds, cfg.ThreatIntel.CustomFeedsDirectory); err != nil {
		return nil, err
	}

	// add online feed sources (with last modified time set to zero)
	getOnlineFeedsList(feeds, cfg.ThreatIntel.OnlineFeeds)

	return feeds, nil
}

// getCustomFeedsList populates the feeds map with the custom feed files contained in a specified directory
// and their last modified times
func getCustomFeedsList(afs afero.Fs, feeds map[string]threatIntelFeed, dirPath string) error {
	logger := zlog.GetLogger()

	feedDir, err := util.ParseRelativePath(dirPath)
	if err != nil {
		return err
	}

	logger.Debug().Str("directory", feedDir).Msg("custom feed directory for threat intel")
	// check if directory is valid
	err = util.ValidateDirectory(afs, feedDir)
	if err != nil {
		// return nil if the directory doesn't exist or contains no files
		if errors.Is(err, util.ErrDirDoesNotExist) || errors.Is(err, util.ErrDirIsEmpty) {
			return nil
		}
		return err
	}

	// walk the directory and add each file to the feeds map
	err = afero.Walk(afs, feedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if filepath.Ext(path) == ".txt" {
				feeds[path] = threatIntelFeed{
					LastModified: info.ModTime().UTC().Truncate(time.Second),
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// getOnlineFeedsList populates the feeds map with the passed in online feed sources (with last modified time set to zero)
func getOnlineFeedsList(feeds map[string]threatIntelFeed, onlineFeedsList []string) {
	for _, feed := range onlineFeedsList {
		feeds[feed] = threatIntelFeed{
			Online: true,
		}
	}
}

// getOnlineFeed gets the feed at the specified URL and returns an io.ReadCloser
func getOnlineFeed(ctx context.Context, url string) (io.ReadCloser, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// getCustomFeed opens the custom feed from the specified path and returns an io.ReadCloser
func getCustomFeed(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (server *ServerConn) updateFeed(entry *threatIntelFeedRecord, lastModified time.Time, feed io.ReadCloser, writeChan chan Data) error {
	// clear feed from database
	if err := server.removeFeedEntries(entry.Hash); err != nil {
		return err
	}

	// update feed record in database
	// update last modified date to the last date the path was modified
	entry.LastModifiedOnDisk = lastModified
	if err := server.createFeedRecord(entry); err != nil {
		return err
	}

	// upload the feed to the database
	if err := parseFeedEntries(entry.Hash, feed, writeChan); err != nil {
		return err
	}
	return nil
}

func (server *ServerConn) addNewFeed(path string, entry *threatIntelFeed, feed io.ReadCloser, writeChan chan Data) error {
	// get hash of the feed path
	hash, err := util.NewFixedStringHash(path)
	if err != nil {
		return err
	}

	// create a new feed record
	record := &threatIntelFeedRecord{
		Hash:               hash,
		Path:               path,
		Online:             entry.Online,
		LastModifiedOnDisk: entry.LastModified,
	}

	// create the feed record in the database
	if err := server.createFeedRecord(record); err != nil {
		return err
	}

	// upload the feed entries to the database
	if err := parseFeedEntries(record.Hash, feed, writeChan); err != nil {
		return err
	}

	return nil
}

func (server *ServerConn) removeFeed(hash util.FixedString) error {
	// remove feed record from threat_intel_feeds table
	if err := server.removeFeedRecord(hash); err != nil {
		return err
	}

	// remove feed entries from threat_intel table
	if err := server.removeFeedEntries(hash); err != nil {
		return err
	}

	return nil
}

// createFeedRecord adds a feed record to the metadatabase to track a threat intel feed
func (server *ServerConn) createFeedRecord(record *threatIntelFeedRecord) error {
	record.LastModified = time.Now().UTC()

	err := server.Conn.Exec(server.ctx, `
		INSERT INTO metadatabase.threat_intel_feeds (
			hash, path, online, last_modified_on_disk, last_modified
		) VALUES (
			unhex(?), ?, ?, ?, ?
		)
	`, record.Hash.Hex(), record.Path, record.Online, record.LastModifiedOnDisk, record.LastModified)
	return err
}

// removeFeedRecord removes a threat intel feed record from the metadatabase collection for threat intel feeds
func (server *ServerConn) removeFeedRecord(hash util.FixedString) error {
	// set context parameters
	ctx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{"hash": hash.Hex()}))

	err := server.Conn.Exec(ctx, `
		DELETE FROM metadatabase.threat_intel_feeds
		WHERE hash = unhex({hash:String})
	`)

	return err
}

// parseFeedEntries parses a feed from an io.ReadCloser and sends valid entries on writeChan
func parseFeedEntries(feedHash util.FixedString, feed io.ReadCloser, writeChan chan Data) error {
	reader := bufio.NewReader(feed)

	for {
		line, readErr := reader.ReadString('\n')

		// if there is an error reading the line and its not the end of the file, return the error
		if readErr != nil && readErr != io.EOF {
			return readErr
		}

		// if this is the end of the file and the final line is empty, just break the loop
		if len(line) < 1 && readErr == io.EOF {
			break
		}

		// skip if line is comment based on  most common comment characters
		if line[0] == '#' || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "<!--") {
			continue
		}

		// remove leading/trailing spaces and newline characters
		line = strings.TrimSpace(line)

		feedEntry := &threatIntelFeedEntry{
			Hash: feedHash,
		}
		// attempt to parse string as IP address
		ip, err := netip.ParseAddr(line)
		if err != nil {
			// if it's not an IP, try parsing as fqdn
			if util.ValidFQDN(line) {
				// send fqdn to writer
				feedEntry.FQDN = line
				writeChan <- feedEntry
			}
		} else {
			// send IP as IPv6 to writer
			feedEntry.IP = ip
			writeChan <- feedEntry
		}

		// if we have reached the end of the file, break the loop
		if readErr == io.EOF {
			break // End of file
		}
	}
	feed.Close()

	return nil
}

// removeFeedEntries removes entries associated with a threat intel feed from the metadatabase
func (server *ServerConn) removeFeedEntries(hash util.FixedString) error {
	// set context parameters
	ctx := clickhouse.Context(server.ctx, clickhouse.WithParameters(clickhouse.Parameters{"hash": hash.Hex()}))

	err := server.Conn.Exec(ctx, `
		DELETE FROM metadatabase.threat_intel
		WHERE hash = unhex({hash:String})
	`)

	return err
}
