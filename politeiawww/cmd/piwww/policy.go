// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// policyCmd gets the server policy information.
type policyCmd struct{}

// Execute executes the policy command.
func (cmd *policyCmd) Execute(args []string) error {
	pr, err := client.Policy()
	if err != nil {
		return err
	}
	return shared.PrintJSON(pr)
}

// policyHelpMsg is the output of the help command when 'policy' is specified.
const policyHelpMsg = `policy

Fetch server policy.

Arguments:
None`
