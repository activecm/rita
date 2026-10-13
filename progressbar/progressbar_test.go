package progressbar_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/activecm/rita/v5/progressbar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_NoTTY verifies that when stderr is not a terminal (e.g. cron, background job),
// New prints a human-readable message and the program runs without error instead of
// crashing with "could not open a new TTY".
func TestNew_NoTTY(t *testing.T) {
	// Tests never have a TTY on stderr, so this always exercises the no-TTY path.
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	// Pre-cancel so the bubbletea program exits on its first tick (within 1s).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bars := progressbar.New(ctx, nil, nil)

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "No terminal detected", "expected no-TTY message on stderr")

	_, runErr := bars.Run()
	assert.NoError(t, runErr, "program should exit cleanly without a TTY")
}
