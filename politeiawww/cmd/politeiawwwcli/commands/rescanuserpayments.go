// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/decred/politeia/politeiawww/api/v1"

// RescanUserPaymentsCmd rescans the logged in user's paywall address and
// makes sure that all payments have been credited to the user's account.
type RescanUserPaymentsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the rescan user payments command.
func (cmd *RescanUserPaymentsCmd) Execute(args []string) error {
	upr := &v1.UserPaymentsRescan{
		UserID: cmd.Args.UserID,
	}

	err := printJSON(upr)
	if err != nil {
		return err
	}

	uprr, err := client.UserPaymentsRescan(upr)
	if err != nil {
		return err
	}

	return printJSON(uprr)
}

// rescanUserPaymentsHelpMsg is the output of the help command when
// 'rescanuserpayments' is specified.
var rescanUserPaymentsHelpMsg = `rescanuserpayments 

Rescan user payments to check for missed payments.

Arguments:
1. userid        (string, required)   User id 

Result:
{
  "newcredits"   ([]uint64)  Credits that were created by the rescan
}`
