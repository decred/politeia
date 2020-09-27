// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// voteResultsCmd gets the votes that have been cast for the specified
// proposal.
type voteResultsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the proposal votes command.
func (cmd *voteResultsCmd) Execute(args []string) error {
	// Prep request payload
	vr := pi.VoteResults{
		Token: cmd.Args.Token,
	}

	// Print request details
	err := shared.PrintJSON(vr)
	if err != nil {
		return err
	}

	vrr, err := client.VoteResults(vr)
	if err != nil {
		return err
	}

	return shared.PrintJSON(vrr)
}

// voteResultsHelpMsg is the output of the help command when 'voteresults' is
// specified.
const voteResultsHelpMsg = `voteresults "token"

Fetch vote results for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token
`
