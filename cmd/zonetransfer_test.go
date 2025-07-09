package cmd_test

import (
	"github.com/activecm/rita/v5/cmd"
	"github.com/urfave/cli/v2"

	"github.com/stretchr/testify/require"
)

func (c *CmdTestSuite) TestZoneTransfer() {
	commands := []*cli.Command{cmd.ZoneTransferCommand}
	flags := []cli.Flag{}

	// create a new app and context
	app, ctx := setupTestApp(commands, flags)

	tests := []struct {
		name          string
		args          []string
		expectedError error
	}{
		{name: "Too Many Arguments", args: []string{"app", "zone-transfer", "bingbong"}, expectedError: cmd.ErrTooManyArguments},
	}
	for _, test := range tests {
		c.Run(test.name, func() {
			require := require.New(c.T())
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
