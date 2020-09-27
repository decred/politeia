// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// voteStatusCmd gets the vote status of the specified proposal.
type voteStatusCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote status command.
func (cmd *voteStatusCmd) Execute(args []string) error {
	vsr, err := client.VoteStatus(cmd.Args.Token)
	if err != nil {
		return err
	}
	return shared.PrintJSON(vsr)
}

// voteStatusHelpMsg is the output of the help command when 'votestatus' is
// specified.
const voteStatusHelpMsg = `votestatus "token"

Fetch vote status for a proposal.

Proposal vote status codes:

'0' - Invalid vote status
'1' - Vote has not been authorized by proposal author
'2' - Vote has been authorized by proposal author
'3' - Proposal vote has been started
'4' - Proposal vote has been finished
'5' - Proposal doesn't exist

Arguments:
1. token       (string, required)  Proposal censorship token`
