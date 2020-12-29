// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// voteInventoryCmd retrieves the censorship record tokens of all public,
// non-abandoned proposals in  inventory categorized by their vote status.
type voteInventoryCmd struct{}

// Execute executes the voteInventoryCmd command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *voteInventoryCmd) Execute(args []string) error {
	// Setup request
	vi := pi.VoteInventory{}

	// Send request. The request and response details are printed to
	// the console.
	err := shared.PrintJSON(vi)
	if err != nil {
		return err
	}
	vir, err := client.VoteInventory(vi)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(vir)
	if err != nil {
		return err
	}

	return nil
}

// voteInventoryHelpMsg is the command help message.
const voteInventoryHelpMsg = `voteinv

Fetch the censorship record tokens for all proposals, categorized by their
vote status. The unvetted tokens are only returned if the logged in user is an
admin.`
