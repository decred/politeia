// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteResults retreives the cast ticket votes for a record.
type cmdVoteResults struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdVoteResults command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteResults) Execute(args []string) error {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert: cfg.HTTPSCert,
		Verbose:   cfg.Verbose,
		RawJSON:   cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Get vote results
	r := tkv1.Results{
		Token: c.Args.Token,
	}
	rr, err := pc.TicketVoteResults(r)
	if err != nil {
		return err
	}

	// Print results summary
	printVoteResults(rr.Votes)

	return nil
}

// voteResultsHelpMsg is printed to stdout by the help command.
const voteResultsHelpMsg = `voteresults "token"

Fetch vote results for a record.

Arguments:
1. token  (string, required)  Record token.
`
