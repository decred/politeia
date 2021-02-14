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
		Status string `positional-arg-name:"status"`
		Page   uint32 `positional-arg-name:"page"`
	} `positional-args:"true" optional:"true"`

	// Unvetted is used to indicate the state that should be sent in
	// the inventory request. This flag is only required when
	// requesting the inventory for a specific status. If a status
	// argument is provided and this flag is not, it will be assumed
	// that the state being requested is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

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

	// Setup state
	var state string
	switch {
	case c.Unvetted:
		state = rcv1.RecordStateUnvetted
	default:
		state = rcv1.RecordStateVetted
	}

	// Setup status and page number
	var status rcv1.RecordStatusT
	if c.Args.Status != "" {
		// Parse status. This can be either the numeric status code or the
		// human readable equivalent.
		status, err = parseRecordStatus(c.Args.Status)
		if err != nil {
			return err
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
		return err
	}

	// Print inventory
	printJSON(ir)

	return nil
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

Valid statuses:
  public
  censored
  abandoned

Arguments:
1. status (string, optional) Status of tokens being requested.
2. page   (uint32, optional) Page number.

Flags:
  --unvetted (bool, optional) Set status of an unvetted record.
`
