// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// commentVoteCmd is used to upvote/downvote a proposal comment using the
// logged in the user.
type commentVoteCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`     // Censorship token
		CommentID string `positional-arg-name:"commentID"` // Comment ID
		Action    string `positional-arg-name:"action"`    // Upvote/downvote action
	} `positional-args:"true" required:"true"`
}

// Execute executes the like comment command.
func (cmd *commentVoteCmd) Execute(args []string) error {
	const actionUpvote = "upvote"
	const actionDownvote = "downvote"

	token := cmd.Args.Token
	commentID := cmd.Args.CommentID
	action := cmd.Args.Action

	// Validate action
	if action != actionUpvote && action != actionDownvote {
		return fmt.Errorf("invalid action %s; the action must be either "+
			"downvote or upvote", action)
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup pi comment vote request
	var vote pi.CommentVoteT
	switch action {
	case actionUpvote:
		vote = pi.CommentVoteUpvote
	case actionDownvote:
		vote = pi.CommentVoteDownvote
	}

	sig := cfg.Identity.SignMessage([]byte(string(pi.PropStateVetted) + token + commentID +
		string(vote)))
	// Parse provided parent id
	ciUint, err := strconv.ParseUint(commentID, 10, 32)
	if err != nil {
		return err
	}
	cv := pi.CommentVote{
		Token:     token,
		State:     pi.PropStateVetted,
		CommentID: uint32(ciUint),
		Vote:      vote,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = shared.PrintJSON(cv)
	if err != nil {
		return err
	}

	// Send request
	cvr, err := client.CommentVote(cv)
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(cvr)
}

// commentVoteHelpMsg is the output for the help command when 'commentvote' is
// specified.
const commentVoteHelpMsg = `commentvote "token" "commentID" "action"

Vote on a comment.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentID   (string, required)   Id of the comment
3. action      (string, required)   Vote (upvote or downvote)
`
