// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// commentVoteCmd is used to upvote/downvote a proposal comment using the
// logged in the user.
type commentVoteCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID string `positional-arg-name:"commentID"`
		Vote      string `positional-arg-name:"vote"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the like comment command.
func (c *commentVoteCmd) Execute(args []string) error {
	votes := map[string]pi.CommentVoteT{
		"upvote":   pi.CommentVoteUpvote,
		"downvote": pi.CommentVoteDownvote,
		"1":        pi.CommentVoteUpvote,
		"-1":       pi.CommentVoteDownvote,
	}

	// Unpack args
	token := c.Args.Token
	commentID, err := strconv.ParseUint(c.Args.CommentID, 10, 32)
	if err != nil {
		return fmt.Errorf("ParseUint(%v): %v", c.Args.CommentID, err)
	}
	vote, ok := votes[c.Args.Vote]
	if !ok {
		return fmt.Errorf("invalid vote option '%v' \n%v",
			c.Args.Vote, commentVoteHelpMsg)
	}

	// Verify identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Sign vote choice
	msg := strconv.Itoa(int(pi.PropStateVetted)) + token +
		c.Args.CommentID + c.Args.Vote
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])

	// Setup request
	cv := pi.CommentVote{
		Token:     token,
		State:     pi.PropStateVetted,
		CommentID: uint32(commentID),
		Vote:      vote,
		Signature: signature,
		PublicKey: cfg.Identity.Public.String(),
	}

	// Send request. The request and response details are printed to
	// the console.
	err = shared.PrintJSON(cv)
	if err != nil {
		return err
	}
	cvr, err := client.CommentVote(cv)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(cvr)
	if err != nil {
		return err
	}

	// Verify receipt
	vr, err := client.Version()
	if err != nil {
		return err
	}
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	receiptb, err := util.ConvertSignature(cvr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), receiptb) {
		return fmt.Errorf("could not verify receipt")
	}

	return nil
}

// commentVoteHelpMsg is the help command message.
const commentVoteHelpMsg = `commentvote "token" "commentID" "vote"

Upvote or downvote a comment as the logged in user.

Arguments:
1. token      (string, required)  Proposal censorship token
2. commentID  (string, required)  Comment ID
3. vote       (string, required)  Upvote or downvote

You can specify either the numeric vote option (1 or -1) or the human readable
vote option.
upvote (1)
downvote (-1)

Example usage
$ commentvote d594fbadef0f93780000 3 downvote
$ commentvote d594fbadef0f93780000 3 -1
`
