package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help edituser'
var EditUserCmdHelpMsg = `edituser "userid" "action" "reason"

Edit the details for the given user id. 

Valid bit flags are:
'1 << 0' - Notification email when status of user's proposal changes
'1 << 1' - Notification email when voting has started on user's proposal
'1 << 2' - Notification email when a proposal is vetted
'1 << 3' - Notification email when a proposal is edited
'1 << 4' - Notification email when voting on a proposal has started
'1 << 5' - Notification email when a new proposal is submitted (admin only)
'1 << 6' - Notification email when a user authorizes vote on proposal (admin only)
'1 << 7' - Notification email when a comment is made on a user's proposal
'1 << 8' - Notification email when a comment is made on a user's comment
  
Arguments:
1. emailnotifications (uint64, optional)  Email notification setting (bit flag)

Request:
{
  "emailnotifications":  (uint64)  Bit flag
}

Response:
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
