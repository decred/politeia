// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pclient "github.com/decred/politeia/politeiawww/client"
)

// proposalPolicy retrieves the pi API policy.
type proposalPolicyCmd struct{}

// Execute executes the proposalPolicyCmd command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *proposalPolicyCmd) Execute(args []string) error {
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
	pr, err := pc.PiPolicy()
	if err != nil {
		return err
	}

	// Print policy
	println(formatJSON(pr))

	return nil
}

// proposalEditHelpMsg is the printed to stdout by the help command.
const proposalPolicyHelpMsg = `proposalpolicy

Fetch the pi API policy.`
