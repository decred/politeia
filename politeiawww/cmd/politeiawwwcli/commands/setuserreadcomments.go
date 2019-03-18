// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"strings"

	"github.com/decred/politeia/politeiawww/api/www/v1"
)

// SetUserReadCommentsCmd is used to upvote/downvote a proposal comment using the
// logged in the user.
type SetUserReadCommentsCmd struct {
	Args struct {
		Token      string `positional-arg-name:"token"`      // Censorship token
		CommentIDs string `positional-arg-name:"commentIDs"` // Comment IDs
	} `positional-args:"true" required:"true"`
}

// Execute executes the like comment command.
func (cmd *SetUserReadCommentsCmd) Execute(args []string) error {

	token := cmd.Args.Token
	commentIDs := strings.Split(cmd.Args.CommentIDs, ",")

	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}

	urc := &v1.SetUserReadComments{
		ReadComments: commentIDs,
	}

	// Print request details
	err := printJSON(urc)
	if err != nil {
		return err
	}

	// Send request
	urcr, err := client.SetUserReadComments(urc, token)
	if err != nil {
		return err
	}

	// Print response details
	return printJSON(urcr)
}

// setUserReadCommentsHelpMsg is the output for the help command when 'setuserreadcomments' is
// specified.
const setUserReadCommentsHelpMsg = `setuserreadcomments "token" "commentIDs"

Vote on a comment.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentIDs   (string, required)  Read Comments ids. Ex: 1,3,5,7

Request:
{
  "token":      (string)  Censorship token
  "commentids":  ([]string)  Read Comment IDs
}

Response:
{}`
