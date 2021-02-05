// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentVotes retrieves the comment upvotes/downvotes for a user on a
// record.
type cmdCommentVotes struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		UserID string `positional-arg-name:"userid"`
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
	)

	// If a user ID was not provided this command assumes the user
	// is requesting their own comment votes.
	if userID == "" {
		// Get user ID of logged in user
		lr, err := client.Me()
		if err != nil {
			if err.Error() == "401" {
				return fmt.Errorf("no user ID provided and no logged in "+
					"user found. Command usage: \n\n%v", commentVotesHelpMsg)
			}
			return err
		}
		userID = lr.UserID
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

	// Get comment votes
	v := cmv1.Votes{
		Token:  token,
		UserID: userID,
	}
	vr, err := pc.CommentVotes(v)
	if err != nil {
		return err
	}

	// Print votes
	if len(vr.Votes) == 0 {
		printf("No comment votes found for user %v\n", userID)
	}
	printCommentVotes(vr.Votes)

	return nil
}

// commentVotesHelpMsg is printed to stdout by the help command.
const commentVotesHelpMsg = `commentvotes "token" "userid"

Get the provided user comment upvote/downvotes for a proposal. If no user ID
is provded then the command will assume the logged in user is requesting their
own comment votes.

Arguments:
1. token   (string, required)  Proposal censorship token
2. userid  (string, optional)  User ID`
