// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// TokenInventory retrieves the censorship record tokens of all proposals in
// the inventory.
type TokenInventoryCmd struct{}

// Execute executes the token inventory command.
func (cmd *TokenInventoryCmd) Execute(args []string) error {
	reply, err := client.TokenInventory()
	if err != nil {
		return err
	}
	return shared.PrintJSON(reply)
}
