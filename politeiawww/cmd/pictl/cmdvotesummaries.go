// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdVoteSummaries retrieves the vote summaries for the provided proposals.
type cmdVoteSummaries struct {
	Args struct {
		Tokens []string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

/*
// Execute executes the cmdVoteSummaries command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteSummaries) Execute(args []string) error {
	// Setup request
	vs := pi.VoteSummaries{
		Tokens: cmd.Args.Tokens,
	}

	// Send request. The request and response details are printed to
	// the console.
	err := shared.PrintJSON(vs)
	if err != nil {
		return err
	}
	vsr, err := client.VoteSummaries(vs)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(vsr)
	if err != nil {
		return err
	}

	return nil
}
*/

// voteSummariesHelpMsg is printed to stdout by the help command.
const voteSummariesHelpMsg = `votesummaries "tokens"

Fetch the vote summaries for the provided proposal tokens.

Example usage:
$ piww votesummaries cda97ace0a4765140000 71dd3a110500fb6a0000
`
