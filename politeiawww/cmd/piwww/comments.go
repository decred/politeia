// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// CommentsCmd retreives the comments for the specified proposal.
type CommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`

	// CLI flags
	Vetted   bool `long:"vetted" optional:"true"`
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the proposal comments command.
func (cmd *CommentsCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Verify state
	var state pi.PropStateT
	switch {
	case cmd.Vetted && cmd.Unvetted:
		return fmt.Errorf("cannot use --vetted and --unvetted simultaneously")
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	case cmd.Vetted:
		state = pi.PropStateVetted
	default:
		return fmt.Errorf("must specify either --vetted or unvetted")
	}

	gcr, err := client.Comments(pi.Comments{
		Token: token,
		State: state,
	})
	if err != nil {
		return err
	}

	return shared.PrintJSON(gcr)
}

// proposalCommentsHelpMsg is the output for the help command when
// 'proposalcomments' is specified.
const proposalCommentsHelpMsg = `proposalcomments "token" 

Get the comments for a proposal.

Arguments:
1. token       (string, required)   Proposal censorship token

Flags:
  --vetted   (bool, optional)    Comment on vetted record.
  --unvetted (bool, optional)    Comment on unvetted reocrd.
`
