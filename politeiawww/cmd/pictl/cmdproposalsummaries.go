// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdPropsoalSummaries retrieves the summaries for the provided proposal
// tokens.
type cmdProposalSummaries struct {
	Args struct {
		Tokens []string `positional-arg-name:"tokens"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdProposalSummaries command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalSummaries) Execute(args []string) error {
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

	// Get vote summaries
	s := piv1.Summaries{
		Tokens: c.Args.Tokens,
	}
	sr, err := pc.PiSummaries(s)
	if err != nil {
		return err
	}

	// Print summaries
	for k, v := range sr.Summaries {
		printProposalSummary(k, v)
		printf("-----\n")
	}

	return nil
}

// proposalSummariesHelpMsg is printed to stdout by the help command.
const proposalSummariesHelpMsg = `proposalsummaries "tokens..."
Fetch the proposal summaries for the provided tokens. This command accepts both
full length tokens and token prefixes.

Example usage:
$ pictl proposalsummaries cda97ace0a476514 71dd3a110500fb6a
$ pictl proposalsummaries cda97ac 71dd3a1`
