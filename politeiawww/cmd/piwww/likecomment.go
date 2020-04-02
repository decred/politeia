// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// LikeCommentCmd is used to upvote/downvote a proposal comment using the
// logged in the user.
type LikeCommentCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`     // Censorship token
		CommentID string `positional-arg-name:"commentID"` // Comment ID
		Action    string `positional-arg-name:"action"`    // Upvote/downvote action
	} `positional-args:"true" required:"true"`
}

// Execute executes the like comment command.
func (cmd *LikeCommentCmd) Execute(args []string) error {
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

	// Setup like comment request
	var actionCode string
	switch action {
	case actionUpvote:
		actionCode = v1.VoteActionUp
	case actionDownvote:
		actionCode = v1.VoteActionDown
	}

	sig := cfg.Identity.SignMessage([]byte(token + commentID + actionCode))
	lc := &v1.LikeComment{
		Token:     token,
		CommentID: commentID,
		Action:    actionCode,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := shared.PrintJSON(lc)
	if err != nil {
		return err
	}

	// Send request
	lcr, err := client.LikeComment(lc)
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(lcr)
}

// likeCommentHelpMsg is the output for the help command when 'likecomment' is
// specified.
const likeCommentHelpMsg = `votecomment "token" "commentID" "action"

Vote on a comment.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentID   (string, required)   Id of the comment
3. action      (string, required)   Vote (upvote or downvote)

Request:
{
  "token":      (string)  Censorship token
  "commentid":  (string)  Id of comment
  "action":     (string)  actionCode (upvote = '1', downvote = '-1')
  "signature":  (string)  Signature of vote (token + commentID + actionCode)
  "publickey":  (string)  Public key used for signature
}

Response:
{
  "total":    (uint64)  Total number of up and down votes
  "result":   (int64)  Current tally of likes (can be negative)
  "receipt":  (string)  Server signature of vote signature
  "error":    (string)  Error if something went wrong during liking a comment
}`
