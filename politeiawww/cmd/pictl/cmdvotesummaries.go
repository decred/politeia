// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteSummaries retrieves the vote summaries for the provided records.
type cmdVoteSummaries struct {
	Args struct {
		Tokens []string `positional-arg-name:"tokens"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdVoteSummaries command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteSummaries) Execute(args []string) error {
	_, err := voteSummaries(c)
	if err != nil {
		return err
	}
	return nil
}

// voteSummaries fetches the ticketvote API Summaries route for a page of
// tokens. This function has been pulled out of the Execute method so that
// it can be used in the test commands.
func voteSummaries(c *cmdVoteSummaries) (map[string]tkv1.Summary, error) {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert: cfg.HTTPSCert,
		Verbose:   cfg.Verbose,
		RawJSON:   cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return nil, err
	}

	// Get vote summaries
	s := tkv1.Summaries{
		Tokens: c.Args.Tokens,
	}
	sr, err := pc.TicketVoteSummaries(s)
	if err != nil {
		return nil, err
	}

	// Print summaries
	for k, v := range sr.Summaries {
		printf(voteSummaryString(k, "", v))
		printf("-----\n")
	}

	return sr.Summaries, nil
}

// voteSummariesHelpMsg is printed to stdout by the help command.
const voteSummariesHelpMsg = `votesummaries "tokens..."

Fetch the vote summaries for the provided records. This command accepts both
full length tokens and token prefixes.

Example usage:
$ pictl votesummaries cda97ace0a476514 71dd3a110500fb6a
$ pictl votesummaries cda97ac 71dd3a1`
