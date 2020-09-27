// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// voteStatusesCmd retreives the vote status of all public proposals.
type voteStatusesCmd struct{}

// Execute executes the vote statuses command.
func (cmd *voteStatusesCmd) Execute(args []string) error {
	avsr, err := client.GetAllVoteStatus()
	if err != nil {
		return err
	}
	return shared.PrintJSON(avsr)
}

// voteStatusesHelpMsg is the output for the help command when 'votestatuses'
// is specified.
const voteStatusesHelpMsg = `votestatuses

Fetch vote status of all public proposals.

Proposal vote status codes:

'0' - Invalid vote status
'1' - Vote has not been authorized by proposal author
'2' - Vote has been authorized by proposal author
'3' - Proposal vote has been started
'4' - Proposal vote has been finished
'5' - Proposal doesn't exist

Arguments: None`
