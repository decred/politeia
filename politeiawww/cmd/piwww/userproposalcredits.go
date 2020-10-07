// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userProposalCreditsCmd gets the proposal credits for the logged in user.
type userProposalCreditsCmd struct{}

// Execute executes the user proposal credits command.
func (cmd *userProposalCreditsCmd) Execute(args []string) error {
	ppdr, err := client.UserProposalCredits()
	if err != nil {
		return err
	}
	return shared.PrintJSON(ppdr)
}

// userProposalCreditsHelpMsg is the output of the help command when
// 'userproposalcredits' is specified.
const userProposalCreditsHelpMsg = `userproposalcredits	

Fetch the logged in user's proposal credits.	

Arguments: None`
