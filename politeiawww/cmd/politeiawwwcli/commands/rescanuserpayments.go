// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/decred/politeia/politeiawww/api/v1"

// Help message displayed for the command 'politeiawwwcli help rescanuserpayments'
var RescanUserPaymentsCmdHelpMsg = `rescanuserpayments 

Rescan user payments to check for missed payments.

Arguments:
1. userid        (string, required)   User id 

Result:
{
  "newcredits"   ([]uint64)  Credits that were created by the rescan
}`

type RescanUserPaymentsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" description:"User ID"`
	} `positional-args:"true" required:"true"`
}

func (cmd *RescanUserPaymentsCmd) Execute(args []string) error {
	upr := &v1.UserPaymentsRescan{
		UserID: cmd.Args.UserID,
	}

	err := Print(upr, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	uprr, err := c.UserPaymentsRescan(upr)
	if err != nil {
		return err
	}

	return Print(uprr, cfg.Verbose, cfg.RawJSON)
}
