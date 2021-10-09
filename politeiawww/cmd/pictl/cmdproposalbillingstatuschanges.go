// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposalBillingStatusChanges returns the billing status changes of a
// proposal.
type cmdProposalBillingStatusChanges struct {
	Args struct {
		Tokens []string `positional-arg-name:"token" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposalBillingStatusChanges command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalBillingStatusChanges) Execute(args []string) error {
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

	// Setup request
	bscs := piv1.BillingStatusChanges{
		Tokens: c.Args.Tokens,
	}

	// Send request
	bscsr, err := pc.PiBillingStatusChanges(bscs)
	if err != nil {
		return err
	}

	// Print billing status changes for all tokens
	for t, bscs := range bscsr.BillingStatusChanges {
		printf("Billing Status Changes of %v\n", t)
		for _, bsc := range bscs {
			printBillingStatusChange(bsc)
			printf("-----\n")
		}
		printf("\n")
	}

	return nil
}

// proposalBillingStatusChangesHelpMsg is printed to stdout by the help command.
const proposalBillingStatusChangesHelpMsg = `proposalbillingstatuschanges "tokens..."

Return the billing status changes for a page of propsoals.

Arguments:
1. tokens   (string, required)   Proposal censorship tokens
`
