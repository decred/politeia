// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteTimestamps retrieves the timestamps for a politeiawww ticket vote.
type cmdVoteTimestamps struct {
	Args struct {
		Token     string `positional-arg-name:"token" required:"true"`
		VotesPage uint32 `positional-arg-name:"votespage" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdVoteTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTimestamps) Execute(args []string) error {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Get timestamps
	t := tkv1.Timestamps{
		Token:     c.Args.Token,
		VotesPage: c.Args.VotesPage,
	}
	tr, err := pc.TicketVoteTimestamps(t)
	if err != nil {
		return err
	}

	// Verify timestamps
	return pclient.TicketVoteTimestampsVerify(*tr)
}

// voteTimestampsHelpMsg is printed to stdout by the help command.
const voteTimestampsHelpMsg = `votetimestamps "token" votepage

Request the timestamps for ticket vote data.

If no votes page number is provided then the vote authorization and vote
details timestamps will be returned. If a votes page number is provided then
the specified page of votes will be returned.

Arguments:
1. token     (string, required) Record token.
2. votepage  (uint32, optional) Page number for cast vote timestamps. 
`
