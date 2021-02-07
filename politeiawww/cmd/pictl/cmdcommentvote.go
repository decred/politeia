// Copyright (c) 2020-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdCommentVote is used to upvote/downvote a proposal comment using the
// logged in the user.
type cmdCommentVote struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID uint32 `positional-arg-name:"commentID"`
		Vote      string `positional-arg-name:"vote"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdCommentVote command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentVote) Execute(args []string) error {
	// Check for user identity. A user identity is required to sign
	// the comment vote.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Parse vote preference
	votes := map[string]cmv1.VoteT{
		"upvote":   cmv1.VoteUpvote,
		"downvote": cmv1.VoteDownvote,
		"1":        cmv1.VoteUpvote,
		"-1":       cmv1.VoteDownvote,
	}
	vote, ok := votes[c.Args.Vote]
	if !ok {
		return fmt.Errorf("invalid vote option '%v' \n%v",
			c.Args.Vote, commentVoteHelpMsg)
	}

	// Setup request
	msg := c.Args.Token + strconv.FormatUint(uint64(c.Args.CommentID), 10) +
		strconv.FormatInt(int64(vote), 10)
	sig := cfg.Identity.SignMessage([]byte(msg))
	v := cmv1.Vote{
		Token:     c.Args.Token,
		CommentID: c.Args.CommentID,
		Vote:      vote,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: cfg.Identity.Public.String(),
	}

	// Send request
	cvr, err := pc.CommentVote(v)
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
	if !serverID.VerifyMessage([]byte(v.Signature), receiptb) {
		return fmt.Errorf("could not verify receipt")
	}

	// Print receipt
	printf("Downvotes: %v\n", int64(cvr.Downvotes)*-1)
	printf("Upvotes  : %v\n", cvr.Upvotes)
	printf("Timestamp: %v\n", timestampFromUnix(cvr.Timestamp))
	printf("Receipt  : %v\n", cvr.Receipt)

	return nil
}

// commentVoteHelpMsg is printed to stdout by the help command.
const commentVoteHelpMsg = `commentvote "token" "commentID" "vote"

Upvote or downvote a comment.

Requires the user to be logged in. Votes can only be cast on vetted records.

Arguments:
1. token      (string, required)  Proposal censorship token
2. commentID  (string, required)  Comment ID
3. vote       (string, required)  Upvote or downvote

You can specify either the numeric vote option (1 or -1) or the human readable
vote option.
upvote (1)
downvote (-1)

Example usage
$ commentvote d594fbadef0f9378 3 downvote
$ commentvote d594fbadef0f9378 3 -1
`
