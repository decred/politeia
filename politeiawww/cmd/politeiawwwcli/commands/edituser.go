// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help edituser'
var EditUserCmdHelpMsg = `edituser "emailnotifications"

Edit email notifications for the currently logged in user. 

Arguments:
1. emailnotifications       (string, required)   Notification option  

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
  "emailnotifications":  (uint64)  Bit flag
}

Response:
{}`

type EditUserCmd struct {
	Args struct {
		NotifType string `long:"emailnotifications" description:"Email notifications"`
	}
}

func (cmd *EditUserCmd) Execute(args []string) error {

	EmailNotifs := map[string]v1.EmailNotificationT{
		"userproposalchange":        1,
		"userproposalvotingstarted": 2,
		"proposalvetted":            4,
		"proposaledited":            8,
		"votingstarted":             16,
		"newproposal":               32,
		"userauthorizedvote":        64,
		"commentonproposal":         128,
		"commentoncomment":          256,
	}

	var notif v1.EmailNotificationT
	a, err := strconv.ParseUint(cmd.Args.NotifType, 10, 64)
	if err == nil {
		// Numeric action code found
		notif = v1.EmailNotificationT(a)
	} else if a, ok := EmailNotifs[cmd.Args.NotifType]; ok {
		// Human readable action code found
		notif = a

	} else if a, ok := EmailNotifs[strings.Split(cmd.Args.NotifType, ",")[0]]; ok {
		// List of human readable action codes found

		notif = a
		// Parse list of strings and calculate associated integer
		s := strings.Split(cmd.Args.NotifType, ",")
		for i := 1; i < len(s); i++ {
			a, ok := EmailNotifs[s[i]]
			if !ok {
				return fmt.Errorf("Invalid edituser option. Type 'help edituser' for list of valid options")
			}
			notif += a
		}

	} else {
		return fmt.Errorf("Invalid edituser option. Type 'help edituser' for list of valid options")
	}

	// Setup request
	helper := uint64(notif)
	eu := &v1.EditUser{
		EmailNotifications: &helper,
	}

	// Print request details
	err = Print(eu, cfg.Verbose, cfg.RawJSON)
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
