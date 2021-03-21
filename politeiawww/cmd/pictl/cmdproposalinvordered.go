// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposalInvOrdered retrieves a page of chronologically ordered censorship
// record tokens. The tokens will include records of all statuses.
type cmdProposalInvOrdered struct {
	Args struct {
		State string `positional-arg-name:"state"`
		Page  uint32 `positional-arg-name:"page"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cmdProposalInvOrdered command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalInvOrdered) Execute(args []string) error {
	_, err := proposalInvOrdered(c)
	if err != nil {
		return err
	}
	return nil
}

// proposalInvOrdered retrieves a page of chronologically ordered proposal
// tokens. This function has been pulled out of the Execute method so that it
// can be used in test commands.
func proposalInvOrdered(c *cmdProposalInvOrdered) (*rcv1.InventoryOrderedReply, error) {
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
		return nil, err
	}

	// Setup state
	var state rcv1.RecordStateT
	if c.Args.State != "" {
		// A state was provided. This can be either the numeric state
		// code or the human readable equivalent.
		state, err = parseRecordState(c.Args.State)
		if err != nil {
			return nil, err
		}
	} else {
		// No state was provided. Default to vetted.
		state = rcv1.RecordStateVetted
	}

	// If a status was given but no page number was given, default to
	// page 1.
	if c.Args.Page == 0 {
		c.Args.Page = 1
	}

	// Get inventory
	i := rcv1.InventoryOrdered{
		State: state,
		Page:  c.Args.Page,
	}
	ir, err := pc.RecordInventoryOrdered(i)
	if err != nil {
		return nil, err
	}

	// Print inventory
	printJSON(ir)

	return ir, nil
}

// proposalInvOrderedHelpMsg is printed to stdout by the help command.
const proposalInvOrderedHelpMsg = `proposalinvordered

Inventory ordered returns a page of record tokens ordered by the timestamp of
their most recent status change from newest to oldest. The reply will include
tokens for all record statuses. Unvetted tokens will only be returned to
admins.

If no state is provided this command defaults to requesting vetted tokens.

If no page number is provided this command defaults to requesting page 1.

Valid states:
  (1) unvetted
  (2) vetted

Arguments:
1. state  (string, optional) State of tokens being requested.
2. page   (uint32, optional) Page number.
`
