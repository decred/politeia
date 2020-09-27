// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// voteDetailsCmd fetches the vote parameters and vote options from the
// politeiawww v2 VoteDetails routes.
type voteDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Proposal token
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote details command.
func (cmd *voteDetailsCmd) Execute(args []string) error {
	vdr, err := client.VoteDetailsV2(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Remove eligible tickets snapshot from the response
	// so that the output is legible.
	if !cfg.RawJSON {
		vdr.EligibleTickets = []string{
			"removed by piwww for readability",
		}
	}

	err = shared.PrintJSON(vdr)
	if err != nil {
		return err
	}

	return nil
}

// voteDetailsHelpMsg is the output of the help command when 'votedetails' is
// specified.
const voteDetailsHelpMsg = `votedetails "token"

Fetch the vote details for a proposal.

Arguments:
1. token    (string, required)  Proposal censorship token
`
