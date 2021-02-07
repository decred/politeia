// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import pclient "github.com/decred/politeia/politeiawww/client"

// cmdVoteInv retrieves the censorship record tokens of all public,
// non-abandoned records in the inventory, categorized by their vote status.
type cmdVoteInv struct{}

// Execute executes the cmdVoteInv command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteInv) Execute(args []string) error {
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

	// Get vote inventory
	ir, err := pc.TicketVoteInventory()
	if err != nil {
		return err
	}

	// Print inventory
	printJSON(ir)

	return nil
}

// voteInvHelpMsg is printed to stdout by the help command.
const voteInvHelpMsg = `voteinv

Fetch the censorship record tokens of all public, non-abandoned records,
categorized by their vote status.`
