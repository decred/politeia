// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentVotes retrieves the comment upvotes/downvotes for a user on a
// record.
type cmdCommentVotes struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		UserID string `positional-arg-name:"userid"`
		Page   uint32 `positional-arg-name:"page"`
	} `positional-args:"true"`
}

// Execute executes the cmdCommentVotes command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentVotes) Execute(args []string) error {
	// Unpack args
	var (
		token  = c.Args.Token
		userID = c.Args.UserID
		page   = c.Args.Page
	)

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

	// Get comment votes
	v := cmv1.Votes{
		Token:  token,
		UserID: userID,
		Page:   page,
	}
	vr, err := pc.CommentVotes(v)
	if err != nil {
		return err
	}

	// Print votes
	if len(vr.Votes) == 0 {
		if userID != "" {
			printf("No comment votes found for user %v\n", userID)
		}
		printf("No comment votes found for proposal %v\n", token)
	}
	printCommentVotes(vr.Votes)

	return nil
}

// commentVotesHelpMsg is printed to stdout by the help command.
const commentVotesHelpMsg = `commentvotes "token" "userid" "page"

Get comment upvote/downvotes for a proposal. User ID can be used to retrieve 
the votes of a specific user. If no filter criteria provided the returned 
votes are paginated. If all votes are requested and no page value is provided 
then the first page is returned.

Arguments:
1. token   (string, required)  Proposal censorship token
2. userid  (string, optional)  User ID
3. page    (uint32, optional)  Requested page`
