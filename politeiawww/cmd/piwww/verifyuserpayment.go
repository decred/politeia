// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// VerifyUserPaymentCmd checks on the status of the logged in user's
// registration payment.
type VerifyUserPaymentCmd struct{}

// Execute executes the verify user payment command.
func (cmd *VerifyUserPaymentCmd) Execute(args []string) error {
	vupr, err := client.VerifyUserPayment()
	if err != nil {
		return err
	}
	return shared.PrintJSON(vupr)
}

// verifyUserPaymentHelpMsg is the output of the help command when
// 'verifyuserpayment' is specified.
var verifyUserPaymentHelpMsg = `verifyuserpayment 

Check if the currently logged in user has paid their user registration fee.

Arguments: None

Result:
{
  "haspaid"                (bool)    Has paid or not
  "paywalladdress"         (string)  Registration paywall address
  "paywallamount"          (uint64)  Registration paywall amount in atoms
  "paywalltxnotbefore"     (int64)   Minimum timestamp for paywall tx
}`
