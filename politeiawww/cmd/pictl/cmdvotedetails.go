// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteDetails retrieves vote details for the provided record.
type cmdVoteDetails struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdVoteDetails command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteDetails) Execute(args []string) error {
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

	// Get vote details
	d := tkv1.Details{
		Token: c.Args.Token,
	}
	dr, err := pc.TicketVoteDetails(d)
	if err != nil {
		return err
	}

	// Print results

	for _, v := range dr.Auths {
		fmt.Printf("Vote authorization\n")
		printAuthDetails(v)
		printf("\n")
	}
	if dr.Vote != nil {
		fmt.Printf("Vote details\n")
		printVoteDetails(*dr.Vote)
	}

	return nil
}

// voteDetailsHelpMsg is printed to stdout by the help command.
const voteDetailsHelpMsg = `votedetails "token"

Fetch the vote details for a record.

Arguments:
1. token  (string, required)  Record token.`
