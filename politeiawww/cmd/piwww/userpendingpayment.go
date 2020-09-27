// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userPendingPaymentCmd sretrieve the payment details for a pending payment,
// if one exists, for the logged in user.
type userPendingPaymentCmd struct{}

// Execute executes the user pending payment command.
func (cmd *userPendingPaymentCmd) Execute(args []string) error {
	pppr, err := client.ProposalPaywallPayment()
	if err != nil {
		return err
	}
	return shared.PrintJSON(pppr)
}

// userPendingPaymentHelpMsg is the output for the help command when
// 'userpendingpayment' is specified.
const userPendingPaymentHelpMsg = `userpendingpayment

Get pending payment details for the logged in user.

Arguments: None`
