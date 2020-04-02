// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
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
	return shared.PrintJSON(gpr)
}
