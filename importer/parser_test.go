package importer

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/activecm/rita/importer/zeektypes"
	"github.com/activecm/rita/util"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestTruncatedTSV(t *testing.T) {
	path := "../test_data/truncated/conn.log"
	entries := make(chan zeektypes.Conn)
	errc := make(chan error)
	metaDBChan := make(chan MetaDBFile)

	// get the current time in microseconds
	start := time.Now().UTC().UnixMicro()

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(start, 10))
	require.NoError(t, err)

	go func() {
		parseFile(afero.NewOsFs(), path, entries, errc, metaDBChan, "test", importID)
		close(errc)
		close(entries)
		close(metaDBChan)
	}()

	receivedTruncatedErr := false
	openChannels := 3
	for openChannels > 0 {
		select {
		case _, ok := <-entries:
			if !ok {
				openChannels--
			}
		case _, ok := <-metaDBChan:
			if !ok {
				openChannels--
			}
		case err, ok := <-errc:
			if !ok {
				openChannels--
			} else if errors.Is(err, errTruncated) {
				receivedTruncatedErr = true
			}

		}
	}

	require.True(t, receivedTruncatedErr)

}

func TestTruncatedHeader(t *testing.T) {
	path := "../test_data/truncated/conn_top.log"
	entries := make(chan zeektypes.Conn)
	errc := make(chan error)
	metaDBChan := make(chan MetaDBFile)

	// get the current time in microseconds
	start := time.Now().UTC().UnixMicro()

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(start, 10))
	require.NoError(t, err)

	go func() {
		parseFile(afero.NewOsFs(), path, entries, errc, metaDBChan, "test", importID)
		close(errc)
		close(entries)
		close(metaDBChan)
	}()

	receivedUnknownFileErr := false
	openChannels := 3
	for openChannels > 0 {
		select {
		case _, ok := <-entries:
			if !ok {
				openChannels--
			}
		case _, ok := <-metaDBChan:
			if !ok {
				openChannels--
			}
		case err, ok := <-errc:
			if !ok {
				openChannels--
			} else if errors.Is(err, errUnknownFileType) {
				receivedUnknownFileErr = true
			}
		}
	}

	require.True(t, receivedUnknownFileErr)
}

func TestTruncatedJSON(t *testing.T) {
	path := "../test_data/truncated/conn_json.log"
	entries := make(chan zeektypes.Conn)
	errc := make(chan error)
	metaDBChan := make(chan MetaDBFile)

	// get the current time in microseconds
	start := time.Now().UTC().UnixMicro()

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(start, 10))
	require.NoError(t, err)

	go func() {
		parseFile(afero.NewOsFs(), path, entries, errc, metaDBChan, "test", importID)
		close(errc)
		close(entries)
		close(metaDBChan)
	}()

	receivedTruncatedErr := false
	openChannels := 3
	for openChannels > 0 {
		select {
		case _, ok := <-entries:
			if !ok {
				openChannels--
			}
		case _, ok := <-metaDBChan:
			if !ok {
				openChannels--
			}
		case err, ok := <-errc:
			if !ok {
				openChannels--
			} else if errors.Is(err, errTruncated) {
				receivedTruncatedErr = true
			}

		}
	}

	require.True(t, receivedTruncatedErr)

}

func TestHasUnknownFieldTSV(t *testing.T) {
	path := "../test_data/has_unknown_field/http.log"

	entries := make(chan zeektypes.HTTP)
	errc := make(chan error)
	metaDBChan := make(chan MetaDBFile)

	// get the current time in microseconds
	start := time.Now().UTC().UnixMicro()

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(start, 10))
	require.NoError(t, err)

	go func() {
		parseFile(afero.NewOsFs(), path, entries, errc, metaDBChan, "test", importID)
		close(errc)
		close(entries)
		close(metaDBChan)
	}()

	receivedErr := false
	openChannels := 3
	recordCount := 0
	for openChannels > 0 {
		select {
		case _, ok := <-entries:
			if !ok {
				openChannels--
			} else {
				recordCount++
			}
		case _, ok := <-metaDBChan:
			if !ok {
				openChannels--
			}
		case err, ok := <-errc:
			if !ok {
				openChannels--
			} else if err != nil {
				receivedErr = true
			}

		}
	}

	require.Equal(t, 5, recordCount, "number of http records")
	require.False(t, receivedErr, "unknown field error")

}

func TestPlainTextFile(t *testing.T) {
	path := "../test_data/text_file/conn.log"

	entries := make(chan zeektypes.Conn)
	errc := make(chan error)
	metaDBChan := make(chan MetaDBFile)

	// get the current time in microseconds
	start := time.Now().UTC().UnixMicro()

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(start, 10))
	require.NoError(t, err)

	go func() {
		parseFile(afero.NewOsFs(), path, entries, errc, metaDBChan, "test", importID)
		close(errc)
		close(entries)
		close(metaDBChan)
	}()

	receivedErr := false
	openChannels := 3
	recordCount := 0
	for openChannels > 0 {
		select {
		case _, ok := <-entries:
			if !ok {
				openChannels--
			} else {
				recordCount++
			}
		case _, ok := <-metaDBChan:
			if !ok {
				openChannels--
			}
		case err, ok := <-errc:
			if !ok {
				openChannels--
			} else if errors.Is(err, errUnknownFileType) {
				receivedErr = true
			}

		}
	}
	require.True(t, receivedErr, "should receive unknown file type error")
}
