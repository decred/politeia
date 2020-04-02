// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// UserPendingPaymentCmd sretrieve the payment details for a pending payment,
// if one exists, for the logged in user.
type UserPendingPaymentCmd struct{}

// Execute executes the user pending payment command.
func (cmd *UserPendingPaymentCmd) Execute(args []string) error {
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

Arguments: None

Response:
{
  "txid"           (string)  Transaction id
  "amount"         (uint64)  Amount sent to paywall address in atoms
  "confirmations"  (uint64)  Number of confirmations of payment tx
}`
