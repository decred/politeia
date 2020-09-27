// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// proposalInventoryCmd retrieves the censorship record tokens of all proposals in
// the inventory.
type proposalInventoryCmd struct{}

// Execute executes the proposal inventory command.
func (cmd *proposalInventoryCmd) Execute(args []string) error {
	reply, err := client.ProposalInventory()
	if err != nil {
		return err
	}

	return shared.PrintJSON(reply)
}

// proposalInventoryHelpMsg is the output of the help command when
// 'proposalinventory' is specified.
const proposalInventoryHelpMsg = `proposalinventory

Fetch the censorship record tokens for all proposals, separated by their
status. The unvetted tokens are only returned if the logged in user is an
admin.`
