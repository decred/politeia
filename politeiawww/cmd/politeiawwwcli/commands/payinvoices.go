// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// PayInvoicesCmd
type PayInvoicesCmd struct {
}

// Execute executes the generate payouts command.
func (cmd *PayInvoicesCmd) Execute(args []string) error {

	// Pay invoices
	pir, err := client.PayInvoices(
		&v1.PayInvoices{})
	if err != nil {
		return err
	}

	// Print user invoices
	return printJSON(pir)
}
