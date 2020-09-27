// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// commentVotesCmd retreives like comment objects for
// the specified proposal from the provided user.
type commentVotesCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`  // Censorship token
		UserID string `positional-arg-name:"userid"` // User id
	} `positional-args:"true" required:"true"`
}

// Execute executes the user comment likes command.
func (cmd *commentVotesCmd) Execute(args []string) error {
	token := cmd.Args.Token
	userID := cmd.Args.UserID

	cvr, err := client.CommentVotes(pi.CommentVotes{
		Token:  token,
		State:  pi.PropStateVetted,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	return shared.PrintJSON(cvr)
}

// commentVotesHelpMsg is the output for the help command when
// 'commentvotes' is specified.
const commentVotesHelpMsg = `commentvotes "token" "userid"

Get the provided user comment upvote/downvotes for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token
2. userid      (string, required)  User id
`
