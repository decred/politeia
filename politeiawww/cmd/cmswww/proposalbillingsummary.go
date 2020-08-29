// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ProposalBillingCmd gets the invoices for the specified user.
type ProposalBillingSummaryCmd struct {
	Args struct {
	} `positional-args:"true" required:"true"`
	Offset int `long:"offset" optional:"true"` // Offset length
	Count  int `long:"count" optional:"true"`  // Page size
}

// Execute executes the user invoices command.
func (cmd *ProposalBillingSummaryCmd) Execute(args []string) error {
	// Get user invoices
	pbsr, err := client.ProposalBillingSummary(
		&v1.ProposalBillingSummary{
			Offset: cmd.Offset,
			Count:  cmd.Count,
		})
	if err != nil {
		return err
	}

	// Print user invoices
	return shared.PrintJSON(pbsr)
}
