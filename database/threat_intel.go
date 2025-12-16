package database

import (
	"bufio"
	"context"
	"fmt"
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
	feeds, walkErrs, err := getThreatIntelFeeds(afs, cfg)
	if err != nil {
		logger.Warn().Err(err).Str("directory", cfg.Env.ThreatIntelCustomFeedsDirectory).Msg("[THREAT INTEL] Failed to load feeds from custom feeds directory, skipping...")
	}
	for _, we := range walkErrs {
		logger.Warn().Err(we.Error).Str("path", we.Path).Msg("[THREAT INTEL] Issue encountered while loading custom feed, skipping...")
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
				// log the error as a warning and continue. do not return an error, as this should not stop the import process
				logger.Warn().Err(err).Str("feed_url", entry.Path).Msg("[THREAT INTEL] Failed to download online feed, could not update feed in database...")

				//NOTE: should we remove the feed from the database if we can't download an updated version?

				//skip to next feed
				continue
			}

		// if file feed has has an oudated last modified date, update as custom feed
		case !entry.LastModifiedOnDisk.Equal(feeds[entry.Path].LastModified):
			logger.Info().Str("feed_path", entry.Path).Msg("[THREAT INTEL] Updating custom feed because it has been modified...")
			// open the feed file
			feed, err = getCustomFeed(afs, entry.Path)
			if err != nil {
				// log the error as a warning and continue. do not return an error, as this should not stop the import process
				logger.Warn().Err(err).Str("feed_path", entry.Path).Msg("[THREAT INTEL] Failed to open custom feed, could not update feed in database...")

				//NOTE: should we remove the feed from the database if we can't download an updated version?

				// skip to next feed
				continue
			}

		// file feed is current, skip to next feed
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
				logger.Info().Str("feed_url", path).Msg("[THREAT INTEL] Adding new online feed...")
				// download the feed
				feed, err = getOnlineFeed(server.GetContext(), path)
				if err != nil {
					// log the error and skip adding the feed, but do not return an error, as this should not stop the import process
					logger.Warn().Err(err).Str("feed_url", path).Msg("[THREAT INTEL] Failed to download online feed, skipping addition to database...")
					// skip to next feed
					continue
				}
			} else {
				logger.Info().Str("feed_path", path).Msg("[THREAT INTEL] Adding new custom feed...")
				// open the feed file
				feed, err = getCustomFeed(afs, path)
				if err != nil {
					// log the error and skip adding the feed, but do not return an error, as this should not stop the import process
					logger.Warn().Err(err).Str("feed_path", path).Msg("[THREAT INTEL] Failed to open custom feed, skipping addition to database...")
					// skip to next feed
					continue
				}
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

// getThreatIntelFeeds parses the threat intel sources from the config file into a feed map
func getThreatIntelFeeds(afs afero.Fs, cfg *config.Config) (map[string]threatIntelFeed, []util.WalkError, error) {
	// initialize feeds map
	feeds := make(map[string]threatIntelFeed)

	// add custom feed sources
	walkErrs, err := getCustomFeedsList(afs, feeds, cfg.Env.ThreatIntelCustomFeedsDirectory)

	// add online feed sources (with last modified time set to zero)
	getOnlineFeedsList(feeds, cfg.RITA.ThreatIntel.OnlineFeeds)

	return feeds, walkErrs, err
}

// getCustomFeedsList populates the feeds map with the custom feed files contained in a specified directory
// and their last modified times
func getCustomFeedsList(afs afero.Fs, feeds map[string]threatIntelFeed, dirPath string) ([]util.WalkError, error) {
	feedDir, err := util.ParseRelativePath(dirPath)
	if err != nil {
		return nil, err
	}

	// check if directory is valid
	if err := util.ValidateDirectory(afs, feedDir); err != nil {
		return nil, err
	}

	var walkErrs []util.WalkError

	// walk the directory and add each file to the feeds map
	if err := afero.Walk(afs, feedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			walkErrs = append(walkErrs, util.WalkError{
				Path:  path,
				Error: err,
			})
		}
		if !info.IsDir() {
			if filepath.Ext(path) == ".txt" {
				feeds[path] = threatIntelFeed{
					LastModified: info.ModTime().UTC().Truncate(time.Second),
				}
			} else {
				// add to walk errors and continue
				walkErrs = append(walkErrs, util.WalkError{
					Path:  path,
					Error: fmt.Errorf("invalid file extension for threat intel feed, must be .txt"),
				})
			}
		}
		return nil
	}); err != nil {
		return walkErrs, err
	}

	return walkErrs, nil
}

// getCustomFeed opens the custom feed from the specified path and returns an io.ReadCloser
func getCustomFeed(afs afero.Fs, path string) (io.ReadCloser, error) {
	if err := util.ValidateFile(afs, path); err != nil {
		return nil, err
	}

	file, err := afs.Open(path)
	if err != nil {
		return nil, err
	}
	return file, nil
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
	// build request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// fail if status code is not OK
	// this is necessary for cases where the domain is valid but the resource is not found (will pass earlier err check)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("request failed: %d (%s)", resp.StatusCode, resp.Status)
	}

	// return response body
	return resp.Body, nil
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
			} else {
				// invalid entry, skip
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
