// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// commentVotesCmd retreives like comment objects for
// the specified proposal from the provided user.
type commentVotesCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		UserID string `positional-arg-name:"userid"`
	} `positional-args:"true"`
	Me bool `long:"me" optional:"true"`
}

// Execute executes the commentVotesCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *commentVotesCmd) Execute(args []string) error {
	token := c.Args.Token
	userID := c.Args.UserID

	if userID == "" && !c.Me {
		return fmt.Errorf("you must either provide a user id or use " +
			"the --me flag to use the user ID of the logged in user")
	}

	// Get user ID of logged in user if specified
	if c.Me {
		lr, err := client.Me()
		if err != nil {
			return err
		}
		userID = lr.UserID
	}

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
2. userid      (string, required)  User ID

Flags:
  --me   (bool, optional)  Use the user ID of the logged in user
`
