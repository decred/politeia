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
type cmdProposalInv struct {
	Args struct {
		State  string `positional-arg-name:"state"`
		Status string `positional-arg-name:"status"`
		Page   uint32 `positional-arg-name:"page"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cmdProposalInv command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalInv) Execute(args []string) error {
	_, err := proposalInv(c)
	if err != nil {
		return err
	}
	return nil
}

// proposalInv retrieves the proposal inventory. This function has been pulled
// out of the Execute method so that it can be used in test commands.
func proposalInv(c *cmdProposalInv) (*rcv1.InventoryReply, error) {
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
		// Parse state. This can be either the numeric state code or the
		// human readable equivalent.
		state, err = parseRecordState(c.Args.State)
		if err != nil {
			return nil, err
		}
	}

	// Setup status and page number
	var status rcv1.RecordStatusT
	if c.Args.Status != "" {
		// Parse status. This can be either the numeric status code or the
		// human readable equivalent.
		status, err = parseRecordStatus(c.Args.Status)
		if err != nil {
			return nil, err
		}

		// If a status was given but no page number was give, default
		// to page number 1.
		if c.Args.Page == 0 {
			c.Args.Page = 1
		}
	}

	// Get inventory
	i := rcv1.Inventory{
		State:  state,
		Status: status,
		Page:   c.Args.Page,
	}
	ir, err := pc.RecordInventory(i)
	if err != nil {
		return nil, err
	}

	// Print inventory
	printJSON(ir)

	return ir, nil
}

// proposalInvHelpMsg is printed to stdout by the help command.
const proposalInvHelpMsg = `proposalinv

Inventory returns the tokens of the records in the inventory, categorized by
record state and record status. The tokens are ordered by the timestamp of
their most recent status change, sorted from newest to oldest.

The status and page arguments can be provided to request a specific page of
record tokens.

If no status is specified then a page of tokens for each status are returned.
The state and page arguments will be ignored.

Valid states:
  (1) unvetted
  (2) vetted

Valid statuses:
  (2) public
  (3) censored
  (4) abandoned

Arguments:
1. state  (string, optional) State of tokens being requested.
2. status (string, optional) Status of tokens being requested.
3. page   (uint32, optional) Page number.
`
