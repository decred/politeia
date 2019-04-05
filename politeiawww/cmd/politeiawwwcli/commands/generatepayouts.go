// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"github.com/decred/politeia/politeiawww/api/cms/v1"
)

// GeneratePayoutsCmd
type GeneratePayoutsCmd struct {
}

// Execute executes the generate payouts command.
func (cmd *GeneratePayoutsCmd) Execute(args []string) error {

	// Generate payouts
	gpr, err := client.GeneratePayouts(
		&v1.GeneratePayouts{})
	if err != nil {
		return err
	}

	// Print user invoices
	return printJSON(gpr)
}
