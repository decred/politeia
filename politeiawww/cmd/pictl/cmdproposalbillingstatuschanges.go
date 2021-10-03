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
		Token string `positional-arg-name:"token" required:"true"`
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
		Token: c.Args.Token,
	}

	// Send request
	bscsr, err := pc.PiBillingStatusChanges(bscs)
	if err != nil {
		return err
	}

	// Print billing status changes
	for _, bsc := range bscsr.BillingStatusChanges {
		printBillingStatusChange(bsc)
		printf("-----\n")
	}

	return nil
}

// proposalBillingStatusChangesHelpMsg is printed to stdout by the help command.
const proposalBillingStatusChangesHelpMsg = `proposalbillingstatuschanges
"token"

Return the billing status changes of a proposal.

Arguments:
1. token   (string, required)   Proposal censorship token
`
