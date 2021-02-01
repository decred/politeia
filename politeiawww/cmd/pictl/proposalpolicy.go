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
	pc, err := pclient.New(cfg.Host, cfg.HTTPSCert, nil, "")
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

// proposalPolicyHelpMsg is the command help message.
const proposalPolicyHelpMsg = `proposalpolicy

Fetch the pi API policy.`
