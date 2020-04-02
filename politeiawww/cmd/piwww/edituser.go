// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// EditUserCmd edits the preferences of the logged in user.
type EditUserCmd struct {
	Args struct {
		NotifType string `long:"emailnotifications"` // Email notification bit field
	} `positional-args:"true" required:"true"`
}

// Execute executes the edit user command.
func (cmd *EditUserCmd) Execute(args []string) error {
	emailNotifs := map[string]v1.EmailNotificationT{
		"userproposalchange":        v1.NotificationEmailMyProposalStatusChange,
		"userproposalvotingstarted": v1.NotificationEmailMyProposalVoteStarted,
		"proposalvetted":            v1.NotificationEmailRegularProposalVetted,
		"proposaledited":            v1.NotificationEmailRegularProposalEdited,
		"votingstarted":             v1.NotificationEmailRegularProposalVoteStarted,
		"newproposal":               v1.NotificationEmailAdminProposalNew,
		"userauthorizedvote":        v1.NotificationEmailAdminProposalVoteAuthorized,
		"commentonproposal":         v1.NotificationEmailCommentOnMyProposal,
		"commentoncomment":          v1.NotificationEmailCommentOnMyComment,
	}

	var notif v1.EmailNotificationT
	a, err := strconv.ParseUint(cmd.Args.NotifType, 10, 64)
	if err == nil {
		// Numeric action code found
		notif = v1.EmailNotificationT(a)
	} else if a, ok := emailNotifs[cmd.Args.NotifType]; ok {
		// Human readable action code found
		notif = a
	} else if strings.Contains(cmd.Args.NotifType, ",") {
		// List of human readable action codes found

		notif = a
		// Parse list of strings and calculate associated integer
		s := strings.Split(cmd.Args.NotifType, ",")
		for _, v := range s {
			a, ok := emailNotifs[v]
			if !ok {
				return fmt.Errorf("Invalid edituser option. Type " +
					"'help edituser' for list of valid options")
			}
			notif |= a
		}
	} else {
		return fmt.Errorf("Invalid edituser option. Type 'help edituser' " +
			"for list of valid options")
	}

	// Setup request
	helper := uint64(notif)
	eu := &v1.EditUser{
		EmailNotifications: &helper,
	}

	// Print request details
	err = shared.PrintJSON(eu)
	if err != nil {
		return err
	}

	// Send request
	eur, err := client.EditUser(eu)
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(eur)
}

// editUserHelpMsg is the output of the help command when 'edituser' is
// specified.
const editUserHelpMsg = `edituser "emailnotifications"

Edit user settings for the logged in user.
 
Arguments:
1. emailnotifications       (string, required)   Email notification bit field

Valid options are:

1.   userproposalchange         Notify when status of my proposal changes
2.   userproposalvotingstarted  Notify when my proposal vote has started
4.   proposalvetted             Notify when any proposal is vetted
8.   proposaledited             Notify when any proposal is edited
16.  votingstarted              Notify when voting on any proposal has started
32.  newproposal                Notify when proposal is submitted (admin only)
64.  userauthorizedvote         Notify when user authorizes vote (admin only)
128. commentonproposal          Notify when comment is made on my proposal
256. commentoncomment           Notify when comment is made on my comment

Request:
{
  "emailnotifications":  (uint64)  Bit field
}

Response:
{}`
