// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userProposalPaywallTxCmd retrieves the payment details for a pending payment,
// if one exists, for the logged in user.
type userProposalPaywallTxCmd struct{}

// Execute executes the user proposal paywall tx command.
func (cmd *userProposalPaywallTxCmd) Execute(args []string) error {
	pppr, err := client.UserProposalPaywallTx()
	if err != nil {
		return err
	}
	return shared.PrintJSON(pppr)
}

// userProposalPaywallTxHelpMsg is the output for the help command when
// 'userproposalpaywalltx' is specified.
const userProposalPaywallTxHelpMsg = `userproposalpaywalltx

Get pending payment details for the logged in user.

Arguments: None`
