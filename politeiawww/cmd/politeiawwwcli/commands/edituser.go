package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help edituser'
var EditUserCmdHelpMsg = `edituser "userid" "action" "reason"

Edit the details for the given user id (admin).

Arguments:
1. emailnotifications       (uint64, optional)   Whether to notify via emails

Result:
{
  "emailnotifications": null
}
{}`

type EditUserCmd struct {
	EmailNotifications *uint64 `long:"emailnotifications" optional:"true" description:"Whether to notify via emails"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	// Setup request
	eu := &v1.EditUser{
		EmailNotifications: cmd.EmailNotifications,
	}

	// Print request details
	err := Print(eu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	eur, err := c.EditUser(eu)
	if err != nil {
		return err
	}

	// Print response details
	return Print(eur, cfg.Verbose, cfg.RawJSON)
}
