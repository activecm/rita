package importer

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/util"

	"github.com/joho/godotenv"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// TestImportProgressBarCleanup checks that an import that returns before parsing any logs
// doesn't leave the progress bar's goroutines running
func TestImportProgressBarCleanup(t *testing.T) {
	require.NoError(t, godotenv.Load("../.env"))

	errValidate := errors.New("could not check which files were imported")
	errImportStarted := errors.New("could not record the import start")

	tests := []struct {
		name          string
		validate      func(map[string][]string) (int, error)
		importStarted func(util.FixedString) error
		wantErr       error
	}{
		{
			name:     "All Files Previously Imported",
			validate: func(map[string][]string) (int, error) { return 0, nil },
			wantErr:  ErrAllFilesPreviouslyImported,
		},
		{
			name:     "File Validation Fails",
			validate: func(map[string][]string) (int, error) { return 0, errValidate },
			wantErr:  errValidate,
		},
		{
			name:          "Import Start Record Fails",
			validate:      func(map[string][]string) (int, error) { return 1, nil },
			importStarted: func(util.FixedString) error { return errImportStarted },
			wantErr:       errImportStarted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := progressBarGoroutines()

			// run enough imports that a leak can't be mistaken for noise
			const numImports = 10
			for range numImports {
				// none of these imports reach the database, so they don't need a connection
				importer, err := NewImporter(&database.DB{}, &config.Config{}, time.Now(), 1, 1, 1)
				require.NoError(t, err)
				importer.validateLogFilesCallback = test.validate
				importer.importStartedCallback = test.importStarted

				err = importer.Import(afero.NewMemMapFs(), map[string][]string{})
				require.ErrorIs(t, err, test.wantErr)
			}

			require.Equal(t, before, progressBarGoroutines(), "progress bar goroutines should not outlive %d imports", numImports)
		})
	}
}

// progressBarGoroutines returns the number of running goroutines that belong to the mpb progress bar library
func progressBarGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	count := 0
	// goroutine stacks are separated by blank lines
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, "github.com/vbauerster/mpb/") {
			count++
		}
	}
	return count
}
