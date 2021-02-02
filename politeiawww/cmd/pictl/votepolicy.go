// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pclient "github.com/decred/politeia/politeiawww/client"
)

// votePolicy retrieves the ticketvote API policy.
type votePolicyCmd struct{}

// Execute executes the votePolicyCmd command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *votePolicyCmd) Execute(args []string) error {
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

	// Get policy
	pr, err := pc.TicketVotePolicy()
	if err != nil {
		return err
	}

	// Print policy
	printJSON(pr)

	return nil
}

// votePolicyHelpMsg is printed to stdout by the help command.
const votePolicyHelpMsg = `votepolicy

Fetch the ticketvote API policy.`
