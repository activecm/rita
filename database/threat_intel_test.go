package database

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/activecm/rita/v5/util"
	"github.com/spf13/afero"

	"github.com/stretchr/testify/require"
)

func TestParseOnlineFeeds(t *testing.T) {
	// TEST IP ONLINE FEED
	timeout := 3 * time.Second
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
		feed, err := getOnlineFeed(context.Background(), "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout)
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
		require.Positive(t, expectedTotal, "expected total should be greater than zero")
		feed.Close()

		// read feed again
		url := "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
		feed, err = getOnlineFeed(context.Background(), url, timeout)
		require.NoError(t, err, "getting online feed should not produce an error")

		// get hash
		hash, err := util.NewFixedStringHash(url)
		require.NoError(t, err, "calculating hash should not produce an error")
		require.NotEmpty(t, hash, "hash should not be empty")

		// parse feed entries
		err = parseFeedEntries(hash, feed, c)
		require.NoError(t, err, "parsing feed entries should not produce an error")

		// close channel and wait for go routine to finish
		feed.Close()
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
		feed, err := getOnlineFeed(context.Background(), url, timeout)
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
		require.Positive(t, total, "at least one fqdn should have been parsed")

	})

	t.Run("Invalid Online Feed", func(t *testing.T) {
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

		// attempt to get feed from non existent domain
		url := "http://nonexistent.domain.abc12345/"
		feed, err := getOnlineFeed(context.Background(), url, timeout)
		require.Error(t, err, "getting online feed should produce an error")
		require.Nil(t, feed, "feed should be nil")

		// attempt to get feed from existing domain but non existent resource
		url = "http://example.com/nonexistentresource.txt"
		feed, err = getOnlineFeed(context.Background(), url, timeout)
		require.Error(t, err, "getting online feed should produce an error")
		require.Nil(t, feed, "feed should be nil")

		// close channel and wait for go routine to finish
		close(d)
		wg.Wait()

		// make sure no entries were parsed
		require.Zero(t, total, "no entries should have been parsed")
	})
}

func TestGetOnlineFeed(t *testing.T) {
	ctx := context.Background()
	timeout := 200 * time.Millisecond

	type testCase struct {
		name      string
		url       string
		setup     func() string
		expectErr []string
	}

	tests := []testCase{
		{
			name: "Valid Entry",
			setup: func() string {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintln(w, "bing bong")
				}))
				t.Cleanup(srv.Close)
				return srv.URL
			},
		},
		{
			name:      "Non-Existent Domain",
			url:       "http://nonexistent.domain.abc12345/",
			expectErr: []string{"request failed"},
		},
		{
			name: "Non-Existent Resource On Existing Domain",
			setup: func() string {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "chicken strip", http.StatusNotFound)
				}))
				t.Cleanup(srv.Close)
				return srv.URL
			},
			expectErr: []string{"404", "Not Found"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// get url
			url := tc.url

			// setup mock server if needed
			if tc.setup != nil {
				url = tc.setup()
			}

			// get online feed
			body, err := getOnlineFeed(ctx, url, timeout)

			// validate error case
			if len(tc.expectErr) > 0 {
				require.Error(t, err, "expected error but did not get one")
				require.Nil(t, body, "body must be nil on error")
				for _, msg := range tc.expectErr {
					require.ErrorContains(t, err, msg, "error message does not contain expected text")
				}
				return
			}

			// validate success case
			require.NoError(t, err, "did not expect an error for this test case")
			require.NotNil(t, body, "body should not be nil for successful fetch")

			data, readErr := io.ReadAll(body)
			require.NoError(t, readErr)
			require.NotEmpty(t, data, "successful response should contain data")

			body.Close()
		})
	}
}

func TestOnlineFeedTimeout(t *testing.T) {
	// short timeout so the test runs quickly
	timeout := 200 * time.Millisecond

	// if getOnlineFeed ignores its timeout, this deadline stops the
	// request so the test fails instead of hanging forever
	const callerDeadline = 10 * time.Second

	tests := []struct {
		name    string
		handler http.HandlerFunc
		// true if the server sends headers before it hangs, so the timeout happens while reading the body
		stallsInBody bool
	}{
		{
			name: "Server Never Responds",
			// hang without sending anything
			handler: func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			},
		},
		{
			name: "Server Stops Partway Through The Feed",
			// send the headers and one entry, then hang
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(w, "192.0.2.1")
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				<-r.Context().Done()
			},
			stallsInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(context.Background(), callerDeadline)
			defer cancel()
			start := time.Now()

			body, err := getOnlineFeed(ctx, srv.URL, timeout)
			if tc.stallsInBody {
				require.NoError(t, err, "the headers should arrive before the server stops")
				defer body.Close()
				_, err = io.ReadAll(body)
			}

			require.Error(t, err, "the download should fail once the server stops sending")
			// timing out well before the safety net shows the timeout did its job
			require.Less(t, time.Since(start), callerDeadline/2, "getOnlineFeed should time out on its own before the context deadline")
		})
	}
}
func TestGetCustomFeed(t *testing.T) {

	type testCase struct {
		name      string
		path      string
		setup     func(afero.Fs) string
		expectErr error
	}

	tests := []testCase{
		{
			name: "Valid File",
			setup: func(afs afero.Fs) string {
				// tmp, err := os.CreateTemp("", "customfeed-*")
				tmp, err := afero.TempFile(afs, "", "customfeed-*.txt")
				require.NoError(t, err)
				t.Cleanup(func() { afs.Remove(tmp.Name()) })

				_, writeErr := tmp.WriteString("bing bong")
				require.NoError(t, writeErr)

				require.NoError(t, tmp.Close())
				return tmp.Name()
			},
		},
		{
			name:      "Non Existent File",
			path:      "/this/does/not/exist.txt",
			expectErr: util.ErrFileDoesNotExist,
		},
		{
			name: "Path Is Directory",
			setup: func(afs afero.Fs) string {
				dir := "/somedir"
				require.NoError(t, afs.MkdirAll(dir, 0o755))
				return dir
			},
			expectErr: util.ErrPathIsDir,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			afs := afero.NewMemMapFs()
			// get path
			path := tc.path
			if tc.setup != nil {
				path = tc.setup(afs)
			}

			// get custom feed
			body, err := getCustomFeed(afs, path)

			// validate error case
			if tc.expectErr != nil {
				require.Error(t, err, "expected error but did not get one")
				require.Nil(t, body, "body must be nil on error")
				require.ErrorContains(t, err, tc.expectErr.Error(), "error message does not contain expected text")

				return
			}

			// validate success case
			require.NoError(t, err, "did not expect an error for this test case")
			require.NotNil(t, body, "body should not be nil for valid file")

			data, readErr := io.ReadAll(body)
			require.NoError(t, readErr)
			require.NotEmpty(t, data, "file should not be empty")

			body.Close()
		})
	}
}

func TestGetCustomFeedsList(t *testing.T) {

	type testCase struct {
		name               string
		setup              func(afs afero.Fs) string
		dirPath            string
		expectErr          error
		expectedWalkErrors []string
		expectFiles        []string
	}

	tests := []testCase{

		{
			name: "Valid Directory With TXT Files",
			setup: func(afs afero.Fs) string {
				dir := "/feeds"
				require.NoError(t, afs.MkdirAll(dir, 0o755))

				require.NoError(t, afero.WriteFile(afs, "/feeds/a.txt", []byte("aaa"), 0o644))
				require.NoError(t, afero.WriteFile(afs, "/feeds/b.txt", []byte("bbb"), 0o644))
				return dir
			},
			expectFiles: []string{"/feeds/a.txt", "/feeds/b.txt"},
		},
		{
			name: "Valid Directory With TXT File and a Non-TXT File",
			setup: func(afs afero.Fs) string {
				dir := "/feeds"
				require.NoError(t, afs.MkdirAll(dir, 0o755))
				require.NoError(t, afero.WriteFile(afs, "/feeds/a.txt", []byte("aaa"), 0o644))
				require.NoError(t, afero.WriteFile(afs, "/feeds/b.txt", []byte("bbb"), 0o644))
				// not-txt file
				require.NoError(t, afero.WriteFile(afs, "/feeds/image.png", []byte("png"), 0o644))
				return dir
			},
			expectFiles:        []string{"/feeds/a.txt", "/feeds/b.txt"},
			expectedWalkErrors: []string{"/feeds/image.png"},
		},
		{
			name: "Directory Contains Only Non TXT Files",
			setup: func(afs afero.Fs) string {
				dir := "/nontxt"
				require.NoError(t, afs.MkdirAll(dir, 0o755))
				require.NoError(t, afero.WriteFile(afs, "/nontxt/a.json", []byte("{}"), 0o644))
				require.NoError(t, afero.WriteFile(afs, "/nontxt/b.csv", []byte("x,y"), 0o644))
				return dir
			},
			expectedWalkErrors: []string{"/nontxt/a.json", "/nontxt/b.csv"},
		},
		{
			name:      "Directory Does Not Exist",
			dirPath:   "/missing",
			expectErr: util.ErrDirDoesNotExist,
		},
		{
			name: "Directory Is Empty",
			setup: func(afs afero.Fs) string {
				dir := "/empty"
				require.NoError(t, afs.MkdirAll(dir, 0o755))
				return dir
			},
			expectErr: util.ErrDirIsEmpty,
		},
		{
			name: "Path Is File Not Directory",
			setup: func(afs afero.Fs) string {
				dir := "/feeds"
				require.NoError(t, afs.MkdirAll(dir, 0o755))
				filePath := "/feeds/file.txt"
				require.NoError(t, afero.WriteFile(afs, filePath, []byte("data"), 0o644))
				return filePath
			},
			expectErr: util.ErrPathIsNotDir,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			afs := afero.NewMemMapFs()
			feeds := make(map[string]threatIntelFeed)

			// get directory path
			dirPath := tc.dirPath
			if tc.setup != nil {
				dirPath = tc.setup(afs)
			}

			// call function
			walkErrs, err := getCustomFeedsList(afs, feeds, dirPath)

			if len(tc.expectedWalkErrors) > 0 || tc.expectErr != nil {
				// validate error case
				if tc.expectErr != nil {
					require.Error(t, err, "expected error but did not get one")
					require.ErrorContains(t, err, tc.expectErr.Error(), "error message does not contain expected text")
				}

				// validate walk errors
				if len(tc.expectedWalkErrors) > 0 {
					require.Len(t, walkErrs, len(tc.expectedWalkErrors), "walk errors length mismatch")
					for i, msg := range tc.expectedWalkErrors {
						require.EqualValues(t, walkErrs[i].Path, msg, "walk error message does not contain expected text")
					}
				}

				return
			} else {
				// validate success case
				require.NoError(t, err, "did not expect an error for this test case")
				require.Empty(t, walkErrs, "did not expect any walk errors for this test case")
			}

			// compare expected feeds
			if tc.expectFiles == nil {
				require.Empty(t, feeds, "feeds map should be empty")
			} else {
				require.Len(t, feeds, len(tc.expectFiles), "feeds map size mismatch")

				for _, f := range tc.expectFiles {
					_, ok := feeds[f]
					require.True(t, ok, "expected feed not found: %s", f)
				}
			}
		})
	}
}
