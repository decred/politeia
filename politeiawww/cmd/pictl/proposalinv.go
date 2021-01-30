// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// proposalInvCmd retrieves the censorship record tokens of all proposals in
// the inventory that match the provided filtering criteria. If no filtering
// criteria is given then the full inventory is returned.
type proposalInvCmd struct {
	UserID string `long:"userid" optional:"true"`
}

/*
// Execute executes the proposalInvCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *proposalInvCmd) Execute(args []string) error {
	p := pi.ProposalInventory{
		UserID: c.UserID,
	}
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
*/

// proposalInvHelpMsg is the command help message.
const proposalInvHelpMsg = `proposalinv

Fetch the censorship record tokens for all proposals that match the provided
filtering criteria. If no filtering criteria is provided, the full proposal
inventory will be returned. The returned proposals are categorized by their
proposal state and proposal status. Unvetted tokens are only returned if the
logged in user is an admin.


Flags:
  --userid  (string, optional)  Filter by user ID
`
