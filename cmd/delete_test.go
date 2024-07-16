package cmd_test

import (
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/database"

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
		// TODO: in order to check the actual deletion step from calling the command, we need a way to
		// pass in or use the test clickhouse DBConnection, right now it gets overridden when load config gets called

		// {
		// 	name:                 "No Wildcards - Database Matching Trimmed Name Exactly",
		// 	args:                 []string{"app", "delete", "--ni", "--config=../config.hjson", "bingbong"},
		// 	dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedDeletedDbs:   []string{"bingbong"},
		// 	expectedRemainingDbs: []string{"prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedError:        nil,
		// },
		// {
		// 	name:                 "Prefix Wildcard - Databases Ending with Trimmed Name",
		// 	args:                 []string{"app", "delete", "--ni", "--config=../config.hjson", "*bingbong"},
		// 	dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong"},
		// 	expectedRemainingDbs: []string{"bingbong123", "prefix_bingbong123"},
		// 	expectedError:        nil,
		// },
		// {
		// 	name:                 "Suffix Wildcard - Databases Starting with Trimmed Name",
		// 	args:                 []string{"app", "delete", "--ni", "--config=../config.hjson", "bingbong*"},
		// 	dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedDeletedDbs:   []string{"bingbong", "bingbong123"},
		// 	expectedRemainingDbs: []string{"prefix_bingbong", "prefix_bingbong123"},
		// 	expectedError:        nil,
		// },
		// {
		// 	name:                 "Both Wildcards - Databases Containing Trimmed Name",
		// 	args:                 []string{"app", "delete", "--ni", "--config=../config.hjson", "*bingbong*"},
		// 	dbs:                  []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		// 	expectedRemainingDbs: []string{},
		// 	expectedError:        nil,
		// },
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

			// run app with test.args
			err := app.RunContext(ctx, test.args)
			if test.expectedError != nil {
				require.Error(err, "error should not be nil")
				require.Contains(err.Error(), test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(err, "error should be nil")
			}

		})
	}

}

func (c *CmdTestSuite) TestRunDeleteCmd() {
	type importDB struct {
		name   string
		logDir string
	}

	tests := []struct {
		name                 string
		entry                string
		afs                  afero.Fs
		dbs                  []importDB
		expectedDeletedDbs   []string
		expectedRemainingDbs []string
		expectedError        error
	}{
		{
			name:  "No Wildcards - Database Matching Trimmed Name Exactly",
			entry: "bingbong",
			afs:   afero.NewOsFs(),
			dbs: []importDB{
				{"bingbong", "../test_data/open_conns/open"},
				{"prefix_bingbong", "../test_data/open_conns/open"},
				{"bingbong123", "../test_data/open_conns/open"},
				{"prefix_bingbong123", "../test_data/open_conns/open"},
			},
			expectedDeletedDbs:   []string{"bingbong"},
			expectedRemainingDbs: []string{"prefix_bingbong", "bingbong123", "prefix_bingbong123"},
		},
		{
			name:  "Prefix Wildcard - Databases Ending with Trimmed Name",
			entry: "*bingbong",
			afs:   afero.NewOsFs(),
			dbs: []importDB{
				{"bingbong", "../test_data/open_conns/open"},
				{"prefix_bingbong", "../test_data/open_conns/open"},
				{"bingbong123", "../test_data/open_conns/open"},
				{"prefix_bingbong123", "../test_data/open_conns/open"},
			},
			expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong"},
			expectedRemainingDbs: []string{"bingbong123", "prefix_bingbong123"},
			expectedError:        nil,
		},
		{
			name:  "Suffix Wildcard - Databases Starting with Trimmed Name",
			entry: "bingbong*",
			afs:   afero.NewOsFs(),
			dbs: []importDB{
				{"bingbong", "../test_data/open_conns/open"},
				{"prefix_bingbong", "../test_data/open_conns/open"},
				{"bingbong123", "../test_data/open_conns/open"},
				{"prefix_bingbong123", "../test_data/open_conns/open"},
			},
			expectedDeletedDbs:   []string{"bingbong", "bingbong123"},
			expectedRemainingDbs: []string{"prefix_bingbong", "prefix_bingbong123"},
			expectedError:        nil,
		},
		{
			name:  "Both Wildcards - Databases Containing Trimmed Name",
			entry: "*bingbong*",
			afs:   afero.NewOsFs(),
			dbs: []importDB{
				{"bingbong", "../test_data/open_conns/open"},
				{"prefix_bingbong", "../test_data/open_conns/open"},
				{"bingbong123", "../test_data/open_conns/open"},
				{"prefix_bingbong123", "../test_data/open_conns/open"},
			},
			expectedDeletedDbs:   []string{"bingbong", "prefix_bingbong", "bingbong123", "prefix_bingbong123"},
			expectedRemainingDbs: []string{},
			expectedError:        nil,
		},
	}

	for _, test := range tests {
		c.Run(test.name, func() {
			t := c.T()
			importStartedAt := time.Now()
			// import all dbs
			for _, db := range test.dbs {
				importResults, err := cmd.RunImportCmd(importStartedAt, c.cfg, test.afs, db.logDir, db.name, false, true)
				require.NoError(t, err, "running import command should not produce an error")
				require.NotNil(t, importResults, "import results should not be nil")
			}

			// trim leading and trailing wildcards
			trimmedName, err := cmd.TrimWildcards(test.entry)
			require.NoError(t, err, "trimming wildcards should not produce an error")

			// validate the trimmed name
			err = cmd.ValidateDatabaseName(trimmedName)
			require.NoError(t, err, "validating database name should not produce an error")

			// run the delete command
			err = cmd.RunDeleteCmd(c.cfg, test.entry, trimmedName, false)
			if test.expectedError != nil {
				require.Contains(t, err.Error(), test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(t, err, "error should be nil")
			}

			// get list of import databases
			dbs, err := c.server.ListImportDatabases()
			require.NoError(t, err, "listing databases should not produce an error")
			dbString := database.GetFlatDatabaseList(dbs)

			// validate that the expected databases were deleted
			for _, db := range test.expectedDeletedDbs {
				require.NotContains(t, dbString, db, "database %s should have been deleted", db)
			}

			// validate that the expected databases remain
			for _, db := range test.expectedRemainingDbs {
				require.Contains(t, dbString, db, "database %s should not have been deleted", db)
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

//nolint:unused // will be used in the future
func validateCommandsExist(t *testing.T, commands []*cli.Command, expected []string) {
	t.Helper()
	expectedCmds := make(map[string]bool)
	for _, expectedCmd := range expected {
		expectedCmds[expectedCmd] = false
	}
	for _, command := range commands {
		if _, ok := expectedCmds[command.Name]; ok {
			expectedCmds[command.Name] = true
		}
	}
	for expectedSubCmd, present := range expectedCmds {
		if !present {
			t.Errorf("expected (sub)command %s is missing", expectedSubCmd)
		}
	}
}
