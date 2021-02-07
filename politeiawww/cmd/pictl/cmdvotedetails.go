// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdVoteDetails retrieves vote details for the specified proposals.
type cmdVoteDetails struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

/*
// Execute executes the cmdVoteDetails command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteDetails) Execute(args []string) error {
	// Setup request
	v := pi.Votes{
		Tokens: c.Args.Tokens,
	}

	// Send request. The request and response details are printed to
	// the console.
	err := shared.PrintJSON(v)
	if err != nil {
		return err
	}
	vr, err := client.Votes(v)
	if err != nil {
		return err
	}
	if !cfg.RawJSON {
		// Remove the eligible ticket pool from the response for
		// readability.
		for k, v := range vr.Votes {
			if v.Vote == nil {
				continue
			}
			v.Vote.EligibleTickets = []string{
				"removed by piwww for readability",
			}
			vr.Votes[k] = v
		}
	}
	err = shared.PrintJSON(vr)
	if err != nil {
		return err
	}

	return nil
}
*/

// voteDetailsHelpMsg is printed to stdout by the help command.
const voteDetailsHelpMsg = `votedetails "token"

Fetch the vote details for a proposal.

Arguments:
1. token  (string, required)  Proposal censorship token.`
