// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteSubmissions retrieves vote details for the provided record.
type cmdVoteSubmissions struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdVoteSubmissions command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteSubmissions) Execute(args []string) error {
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

	// Get vote details
	s := tkv1.Submissions{
		Token: c.Args.Token,
	}
	sr, err := pc.TicketVoteSubmissions(s)
	if err != nil {
		return err
	}

	// Print submissions
	printJSON(sr)

	return nil
}

// voteSubmissionsHelpMsg is printed to stdout by the help command.
const voteSubmissionsHelpMsg = `votesubmissions "token"

Get the list of submissions for a runoff vote. The token should be the token of
the runoff vote parent record.

Arguments:
1. token  (string, required)  Record token.`
