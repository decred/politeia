// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdRecordPolicy retrieves the records API policy.
type cmdRecordPolicy struct{}

// Execute executes the cmdRecordPolicy command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdRecordPolicy) Execute(args []string) error {
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
	pr, err := pc.RecordPolicy()
	if err != nil {
		return err
	}

	// Print policy
	printJSON(pr)

	return nil
}

// recordPolicyHelpMsg is the printed to stdout by the help command.
const recordPolicyHelpMsg = `recordpolicy

Fetch the records API policy.`
