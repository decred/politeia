// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposalInv retrieves the censorship record tokens of all proposals in
// the inventory, categorized by status.
type cmdProposalInv struct{}

// Execute executes the cmdProposalInv command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalInv) Execute(args []string) error {
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

	// Get inventory
	ir, err := pc.RecordInventory(rcv1.Inventory{})
	if err != nil {
		return err
	}

	// Print inventory
	printJSON(ir)

	return nil
}

// proposalInvHelpMsg is printed to stdout by the help command.
const proposalInvHelpMsg = `proposalinv

Retrieve the censorship record tokens of all proposals in the inventory,
categorized by status. Unvetted proposals are only returned to admins.`
