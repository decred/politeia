// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// proposalDetails retrieves a full proposal record.
type cmdProposalDetails struct {
	Args struct {
		Token   string `positional-arg-name:"token"`
		Version uint32 `postional-arg-name:"version" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposalDetails command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalDetails) Execute(args []string) error {
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

	// Get proposal details
	d := rcv1.Details{
		Token:   c.Args.Token,
		Version: c.Args.Version,
	}
	r, err := pc.RecordDetails(d)
	if err != nil {
		return err
	}

	// Print proposal to stdout
	err = printProposal(*r)
	if err != nil {
		return err
	}

	return nil
}

// proposalDetailsHelpMsg is printed to stdout by the help command.
const proposalDetailsHelpMsg = `proposaldetails [flags] "token" "version"

Retrieve a full proposal record.

This command accepts both the full tokens or the shortened token prefixes.

Arguments:
1. token  (string, required)  Proposal token.
`
