// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// proposalInventoryCmd retrieves the censorship record tokens of all proposals
// in the inventory.
type proposalInventoryCmd struct{}

// Execute executes the proposal inventory command.
func (cmd *proposalInventoryCmd) Execute(args []string) error {
	p := pi.ProposalInventory{}
	err := shared.PrintJSON(p)
	if err != nil {
		return err
	}
	pir, err := client.ProposalInventory(p)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(pir)
	if err != nil {
		return err
	}
	return nil
}

// proposalInventoryHelpMsg is the command help message.
const proposalInventoryHelpMsg = `proposalinv

Fetch the censorship record tokens for all proposals, categorized by their
proposal state and proposal status. Unvetted tokens are only returned if the
logged in user is an admin.
`
