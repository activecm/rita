package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLabCommandIsRegistered(t *testing.T) {
	var found bool
	for _, command := range Commands() {
		if command.Name == "lab" {
			found = true
			break
		}
	}
	require.True(t, found)
}

func TestLabWindow(t *testing.T) {
	window, err := labWindow("", "30m")
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, window)
	_, err = labWindow("0m", "30m")
	require.Error(t, err)
}
