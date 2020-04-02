// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// UserInvoicesCmd gets the invoices for the specified user.
type UserInvoicesCmd struct {
	Args struct {
		//UserID string `positional-arg-name:"userID"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user invoices command.
func (cmd *UserInvoicesCmd) Execute(args []string) error {
	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get user invoices
	uir, err := client.UserInvoices(
		&v1.UserInvoices{})
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

// userInvoicesHelpMsg is the output of the help command when 'userinvoices'
// is specified.
const userInvoicesHelpMsg = `userinvoices "userID" 

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
