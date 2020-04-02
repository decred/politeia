// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// AdminInvoicesCmd gets all invoices by month/year and/or status.
type AdminInvoicesCmd struct {
	Args struct {
		Month  int `long:"month"`
		Year   int `long:"year"`
		Status int `long:"status"`
	}
}

// Execute executes the admin invoices command.
func (cmd *AdminInvoicesCmd) Execute(args []string) error {
	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get admin invoices
	uir, err := client.AdminInvoices(
		&v1.AdminInvoices{
			Month:  uint16(cmd.Args.Month),
			Year:   uint16(cmd.Args.Year),
			Status: v1.InvoiceStatusT(cmd.Args.Status),
		})
	if err != nil {
		return err
	}

	// Verify invoice censorship records
	for _, p := range uir.Invoices {
		err := verifyInvoice(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify invoice %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user invoices
	return shared.PrintJSON(uir)
}

// userProposalsHelpMsg is the output of the help command when 'userinvoices'
// is specified.
const adminInvoicesHelpMsg = `userinvoices "userID" 

Fetch all invoices submitted by a specific user.

Arguments:
1. userID      (string, required)   User id

Result:
{
  "invoices": [
		{
			...
    }
  ]
}`
