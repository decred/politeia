// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// voteInventoryCmd retrieves the censorship record tokens of all public,
// non-abandoned proposals in  inventory categorized by their vote status.
type voteInventoryCmd struct{}

// Execute executes the vote inventory command.
func (cmd *voteInventoryCmd) Execute(args []string) error {
	reply, err := client.VoteInventory()
	if err != nil {
		return err
	}

	return shared.PrintJSON(reply)
}

// voteInventoryHelpMsg is the output of the help command when
// 'voteinventory' is specified.
const voteInventoryHelpMsg = `voteinventory

Fetch the censorship record tokens for all proposals, separated by their
vote status. The unvetted tokens are only returned if the logged in user is an
admin.`
