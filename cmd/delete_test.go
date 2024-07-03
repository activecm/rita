package cmd_test

import (
	"testing"
	"time"

	"github.com/activecm/rita/cmd"
	"github.com/activecm/rita/database"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func (c *CmdTestSuite) TestDeleteCommand() {
	commands := []*cli.Command{cmd.DeleteCommand}
	flags := []cli.Flag{}

	tests := []struct {
		name                 string
		args                 []string
		dbs                  []string
		expectedDeletedDbs   []string
		expectedRemainingDbs []string
		expectedError        error
	}{
		{
			name:                 "No Wildcards - Database Matching Trimmed Name Exactly",
			args:                 []string{"app", "delete", "--ni", "bingbong"},
			dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedDeletedDbs:   []string{"bingbong"},
			expectedRemainingDbs: []string{"prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedError:        nil,
		},
		{
			name:                 "Prefix Wildcard - Databases Ending with Trimmed Name",
			args:                 []string{"app", "delete", "--ni", "*bingbong"},
			dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong"},
			expectedRemainingDbs: []string{"bingbong123", "prefix_bingbong123"},
			expectedError:        nil,
		},
		{
			name:                 "Suffix Wildcard - Databases Starting with Trimmed Name",
			args:                 []string{"app", "delete", "--ni", "bingbong*"},
			dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedDeletedDbs:   []string{"bingbong", "bingbong123"},
			expectedRemainingDbs: []string{"prefix_bingbong", "prefix_bingbong123"},
			expectedError:        nil,
		},
		{
			name:                 "Both Wildcards - Databases Containing Trimmed Name",
			args:                 []string{"app", "delete", "--ni", "*bingbong*"},
			dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedRemainingDbs: []string{},
			expectedError:        nil,
		},
		{
			name:          "Too Many Arguments",
			args:          []string{"app", "delete", "dbname", "extra"},
			expectedError: cmd.ErrTooManyArguments,
		},
		{
			name:          "No Arguments",
			args:          []string{"app", "delete"},
			expectedError: cmd.ErrMissingDatabaseName,
		},
	}

	for _, test := range tests {
		c.Run(test.name, func() {
			require := require.New(c.T())

			// create a new app and context
			app, ctx := setupTestApp(commands, flags)

			// import new databases
			for _, db := range test.dbs {
				_, err := cmd.RunImportCmd(time.Now(), c.cfg, afero.NewOsFs(), "../test_data/open_conns/open", db, false, false)
				require.NoError(err, "importing data should not produce an error")
			}

			// run app with test.args
			err := app.RunContext(ctx, test.args)
			if test.expectedError != nil {
				require.Error(err, "error should not be nil")
				require.Contains(err.Error(), test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(err, "error should be nil")
			}

			// validate that the expected databases were deleted
			dbs, err := c.server.ListImportDatabases()
			dbString := database.GetFlatDatabaseList(dbs)

			require.NoError(err, "listing databases should not produce an error")

			for _, db := range test.expectedDeletedDbs {
				require.NotContains(dbString, db, "database %s should have been deleted", db)
			}

			// validate that the expected databases remain
			for _, db := range test.expectedRemainingDbs {
				require.Contains(dbString, db, "database %s should not have been deleted", db)
			}

		})
	}

}

func TestTrimWildcards(t *testing.T) {
	tests := []struct {
		name          string
		dbName        string
		want          string
		expectedError error
	}{
		{"Start Wildcard", "*bingbong", "bingbong", nil},
		{"End Wildcard", "bingbong*", "bingbong", nil},
		{"Both Wildcards", "*bingbong*", "bingbong", nil},
		{"No Wildcard", "bingbong", "bingbong", nil},
		{"Only Wildcard", "*", "", cmd.ErrTrimmedNameEmpty},
		{"Only Wildcards", "**", "", cmd.ErrTrimmedNameEmpty},
		{"Empty String", "", "", cmd.ErrTrimmedNameEmpty},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trimmedName, err := cmd.TrimWildcards(test.dbName)
			require.Equal(t, test.expectedError, err, "error should match expected value")
			require.Equal(t, test.want, trimmedName, "trimmed name should match expected value")
		})
	}
}

func validateCommandsExist(t *testing.T, commands []*cli.Command, expected []string) {
	expectedCmds := make(map[string]bool)
	for _, expectedCmd := range expected {
		expectedCmds[expectedCmd] = false
	}
	for _, cmd := range commands {
		if _, ok := expectedCmds[cmd.Name]; ok {
			expectedCmds[cmd.Name] = true
		}
	}
	for expectedSubCmd, present := range expectedCmds {
		if !present {
			t.Errorf("expected (sub)command %s is missing", expectedSubCmd)
		}
	}
}
