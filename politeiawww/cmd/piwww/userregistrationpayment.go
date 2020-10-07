// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userRegistrationPaymentCmd checks on the status of the logged in user's
// registration payment.
type userRegistrationPaymentCmd struct{}

// Execute executes the user registration payment command.
func (cmd *userRegistrationPaymentCmd) Execute(args []string) error {
	vupr, err := client.UserRegistrationPayment()
	if err != nil {
		return err
	}
	return shared.PrintJSON(vupr)
}

// userRegistrationPaymentHelpMsg is the output of the help command when
// 'userregistrationpayment' is specified.
var userRegistrationPaymentHelpMsg = `userregistrationpayment 

Check if the currently logged in user has paid their user registration fee.

Arguments: None`
