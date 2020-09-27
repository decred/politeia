// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// userPaymentsRescanCmd rescans the logged in user's paywall address and
// makes sure that all payments have been credited to the user's account.
type userPaymentsRescanCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the rescan user payments command.
func (cmd *userPaymentsRescanCmd) Execute(args []string) error {
	upr := &v1.UserPaymentsRescan{
		UserID: cmd.Args.UserID,
	}

	err := shared.PrintJSON(upr)
	if err != nil {
		return err
	}

	uprr, err := client.UserPaymentsRescan(upr)
	if err != nil {
		return err
	}

	return shared.PrintJSON(uprr)
}

// userPaymentsRescanHelpMsg is the output of the help command when
// 'rescanuserpayments' is specified.
var userPaymentsRescanHelpMsg = `userpaymentsrescan 

Rescan user payments to check for missed payments.

Arguments:
1. userid        (string, required)   User id`
