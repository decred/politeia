// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userProposalPaywallCmd gets paywall info for the logged in user.
type userProposalPaywallCmd struct{}

// Execute executes the proposal paywall command.
func (cmd *userProposalPaywallCmd) Execute(args []string) error {
	ppdr, err := client.UserProposalPaywall()
	if err != nil {
		return err
	}
	return shared.PrintJSON(ppdr)
}

// userProposalPaywallHelpMsg is the output of the help command when
// 'userproposalpaywall' is specified.
const userProposalPaywallHelpMsg = `userproposalpaywall	

Fetch proposal paywall details.	

Arguments: None`
