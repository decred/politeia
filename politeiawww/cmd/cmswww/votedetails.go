// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// VoteDetailsCmd fetches the vote parameters and vote options from the
// politeiawww v2 VoteDetails routes.
type VoteDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Proposal token
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote details command.
func (cmd *VoteDetailsCmd) Execute(args []string) error {
	vdr, err := client.VoteDetailsDCC(v1.VoteDetails{Token: cmd.Args.Token})
	if err != nil {
		return err
	}

	err = shared.PrintJSON(vdr)
	if err != nil {
		return err
	}

	return nil
}

// voteDetailsHelpMsg is the output of the help command when 'votedetails' is
// specified.
const voteDetailsHelpMsg = `votedetails "token"

Fetch the vote details for a dcc.

Arguments:
1. token    (string, required)  Proposal censorship token
`
