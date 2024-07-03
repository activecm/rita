package database

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/activecm/ritav2/util"

	"github.com/stretchr/testify/require"
)

func TestParseOnlineFeeds(t *testing.T) {
	// TEST IP ONLINE FEED
	t.Run("IP Online Feed", func(t *testing.T) {
		// should be able to parse Feodo tracker
		c := make(chan Data)
		expectedTotal := 0
		total := 0

		// make a go routine to read from the channel and increment total
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range c {
				total++
			}
		}()

		// get expected total from last line of feed
		feed, err := getOnlineFeed(context.Background(), "https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
		require.NoError(t, err, "getting online feed should not error")
		reader := bufio.NewReader(feed)
		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "# END") {
				re := regexp.MustCompile(`\d+`)
				// Find the first match
				match := re.FindString(line)
				require.NotEmpty(t, match, "match should not be empty")

				// Convert the matched string to an integer
				number, err := strconv.Atoi(match)
				require.NoError(t, err, "converting string to int should not error")
				expectedTotal = number
			}
			if err == io.EOF {
				break // End of file
			}
		}
		// make sure expected total is greater than zero
		require.Greater(t, expectedTotal, 0, "expected total should be greater than zero")
		feed.Close()

		// read feed again
		url := "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
		feed, err = getOnlineFeed(context.Background(), url)
		require.NoError(t, err, "getting online feed should not produce an error")

		// get hash
		hash, err := util.NewFixedStringHash(url)
		require.NoError(t, err, "calculating hash should not produce an error")
		require.NotEmpty(t, hash, "hash should not be empty")

		// parse feed entries
		err = parseFeedEntries(hash, feed, c)
		require.NoError(t, err, "parsing feed entries should not produce an error")

		// close channel and wait for go routine to finish
		close(c)
		wg.Wait()

		// verify that feed matches expected total
		require.EqualValues(t, expectedTotal, total, "total should match expected value")
	})

	// TEST DOMAIN ONLINE FEED
	t.Run("Domain Online Feed", func(t *testing.T) {
		// create a channel to mimic the writer which would receive the parsed data
		d := make(chan Data)
		total := 0

		// make a go routine to read from the channel and increment total
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range d {
				total++
			}
		}()

		// get feed
		url := "https://publicsuffix.org/list/public_suffix_list.dat"
		feed, err := getOnlineFeed(context.Background(), url)
		require.NoError(t, err, "getting online feed should not error")

		// get hash
		hash, err := util.NewFixedStringHash(url)
		require.NoError(t, err, "calculating hash should not error")
		require.NotEmpty(t, hash, "hash should not be empty")

		// parse feed entries
		err = parseFeedEntries(hash, feed, d)
		require.NoError(t, err, "parsing feed entries should not error")

		// close channel and wait for go routine to finish
		close(d)
		wg.Wait()

		// make sure at least one fqdn was parsed
		require.Greater(t, total, 0, "at least one fqdn should have been parsed")

	})
}
