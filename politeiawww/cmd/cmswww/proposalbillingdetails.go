// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ProposalBillingCmd gets the invoices for the specified user.
type ProposalBillingDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user invoices command.
func (cmd *ProposalBillingDetailsCmd) Execute(args []string) error {
	// Get user invoices
	pbr, err := client.ProposalBillingDetails(
		&v1.ProposalBillingDetails{
			Token: cmd.Args.Token,
		})
	if err != nil {
		return err
	}

	// Print user invoices
	return shared.PrintJSON(pbr)
}
