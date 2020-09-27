// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// votesCmd retrieves vote details for a proposal, tallies the votes,
// and displays the result.
type votesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the tally command.
func (cmd *votesCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Prep request payload
	v := pi.Votes{
		Tokens: []string{token},
	}

	// Print request details
	err := shared.PrintJSON(v)
	if err != nil {
		return err
	}

	// Get vote detials for proposal
	vrr, err := client.Votes(v)
	if err != nil {
		return fmt.Errorf("ProposalVotes: %v", err)
	}

	// Remove eligible tickets snapshot from response
	// so that the output is legible
	var (
		pv pi.ProposalVote
		ok bool
	)
	if pv, ok = vrr.Votes[token]; ok && !cfg.RawJSON {
		pv.Vote.EligibleTickets = []string{
			"removed by politeiawwwcli for readability",
		}
		vrr.Votes[token] = pv
	}

	// Print response details
	return shared.PrintJSON(vrr)
}

// votesHelpMsg is the output for the help command when 'votes' is specified.
const votesHelpMsg = `votes "token"

Fetch the vote details for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token
`
