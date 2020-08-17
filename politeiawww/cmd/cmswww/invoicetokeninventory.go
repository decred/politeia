// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// InvoiceTokenInventoryCmd retrieves the tokens of all invoices in the inventory.
type InvoiceTokenInventoryCmd struct {
	TimestampMax int64 `long:"timestampmax" optional:"true" description:"Timestamp Max"`
	TimestampMin int64 `long:"timestampmin" optional:"true" description:"Timestamp Min"`
}

// Execute executes the invoice token inventory command.
func (cmd *InvoiceTokenInventoryCmd) Execute(args []string) error {
	reply, err := client.InvoiceTokenInventory(
		&v1.InvoiceTokenInventory{
			TimestampMax: cmd.TimestampMax,
			TimestampMin: cmd.TimestampMin,
		})
	if err != nil {
		return err
	}

	return shared.PrintJSON(reply)
}

// invoiceTokenInventoryHelpMsg is the output of the help command when 'tokeninventory'
// is specified.
const invoiceTokenInventoryHelpMsg = `tokeninventory [flags] 

Fetch invoice tokens by status.

Flags:
  --timestampMax           (int64, optional)   Upper limit for invoice timestamps
  --timestampMin           (int64, optional)   Lower limit for invoice timestamps

Result:
{
	"unreviewed": [
		"23b16d89bdfc28eb2eb2df8ff47176cf9e3f7dc21a6f0981eb63704a8e22373a",		
		"e02378d40b8b9240a8ba1e53419577683f02e71edf1e4865fc54b5477b31c9c5"
	],
	"updated": [
		"2d9a58e55d17cdce496c1c8e9780828e9fdb7a727962a6ca498c91d9ceca5ebb"
	],
	"disputed": [],
	"approved": [],
	"paid": [],
	"rejected": []	  
}`
