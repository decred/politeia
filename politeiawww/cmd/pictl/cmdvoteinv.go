// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteInv retrieves the censorship record tokens of the public records in
// the inventory, categorized by their vote status.
type cmdVoteInv struct {
	Args struct {
		Status string `positional-arg-name:"status"`
		Page   uint32 `positional-arg-name:"page"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cmdVoteInv command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteInv) Execute(args []string) error {
	_, err := voteInv(c)
	if err != nil {
		return err
	}
	return nil
}

// voteInv returns the vote inventory. It has been pulled out of Execute so
// that it can be used in test commands.
func voteInv(c *cmdVoteInv) (map[string][]string, error) {
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

	// Setup status and page number
	var status tkv1.VoteStatusT
	if c.Args.Status != "" {
		// Parse status. This can be either the numeric status code or the
		// human readable equivalent.
		status, err = parseVoteStatus(c.Args.Status)
		if err != nil {
			return nil, err
		}

		// If a status was given but no page number was give, default
		// to page number 1.
		if c.Args.Page == 0 {
			c.Args.Page = 1
		}
	}

	// Get vote inventory
	i := tkv1.Inventory{
		Status: status,
		Page:   c.Args.Page,
	}
	ir, err := pc.TicketVoteInventory(i)
	if err != nil {
		return nil, err
	}

	// Print inventory
	printJSON(ir)

	return ir.Vetted, nil

}

func parseVoteStatus(status string) (tkv1.VoteStatusT, error) {
	// Parse status. This can be either the numeric status code or the
	// human readable equivalent.
	var (
		vs tkv1.VoteStatusT

		statuses = map[string]tkv1.VoteStatusT{
			"unauthorized": tkv1.VoteStatusUnauthorized,
			"authorized":   tkv1.VoteStatusAuthorized,
			"started":      tkv1.VoteStatusStarted,
			"approved":     tkv1.VoteStatusApproved,
			"rejected":     tkv1.VoteStatusRejected,
			"1":            tkv1.VoteStatusUnauthorized,
			"2":            tkv1.VoteStatusAuthorized,
			"3":            tkv1.VoteStatusStarted,
			"5":            tkv1.VoteStatusApproved,
			"6":            tkv1.VoteStatusRejected,
		}
	)
	u, err := strconv.ParseUint(status, 10, 32)
	if err == nil {
		// Numeric status code found
		vs = tkv1.VoteStatusT(u)
	} else if s, ok := statuses[status]; ok {
		// Human readable status code found
		vs = s
	} else {
		return vs, fmt.Errorf("invalid status '%v'", status)
	}

	return vs, nil
}

// voteInvHelpMsg is printed to stdout by the help command.
const voteInvHelpMsg = `voteinv

Inventory requests the tokens of public records in the inventory categorized by
vote status.

The status and page arguments can be provided to request a specific page of
record tokens.

If no status is provided then a page of tokens for all statuses will be
returned. The page argument will be ignored.

Valid statuses:
  ("1") "unauthorized"
  ("2") "authorized"
  ("3") "started"
  ("5") "approved"
  ("6") "rejected"

Arguments:
1. status (string, optional) Status of tokens being requested.
2. page   (uint32, optional) Page number.
`
