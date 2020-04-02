// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// UserLikeCommentsCmd retreives the logged in user's like comment objects for
// the specified proposal.
type UserLikeCommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the user comment likes command.
func (cmd *UserLikeCommentsCmd) Execute(args []string) error {
	cvr, err := client.UserCommentsLikes(cmd.Args.Token)
	if err != nil {
		return err
	}
	return shared.PrintJSON(cvr)
}

// userLikeCommentsHelpMsg is the output for the help command when
// 'userlikecomments' is specified.
const userLikeCommentsHelpMsg = `userlikecomments "token"

Get the logged in user's comment upvote/downvotes for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token

Result:

{
  "commentslikes": [
    {
      "action":    (string)  Vote (upvote or downvote)
      "commentid"  (string)  ID of the comment
      "token":     (string)  Proposal censorship token
    },
  ]
}`
