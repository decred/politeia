// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// votesCmd retrieves vote details for the specified proposals.
type votesCmd struct {
	Args struct {
		Tokens []string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

/*
// Execute executes the votesCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *votesCmd) Execute(args []string) error {
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

// votesHelpMsg is the help command message.
const votesHelpMsg = `votes "tokens"

Fetch the vote details for the provided proposal tokens.

Arguments:
1. tokens  (string, required)  Proposal censorship tokens

Example usage:
$ piwww votes cda97ace0a4765140000 71dd3a110500fb6a0000
`
