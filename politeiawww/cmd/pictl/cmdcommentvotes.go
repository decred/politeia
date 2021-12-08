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
		Token string `positional-arg-name:"token" required:"true"`
	} `positional-args:"true"`

	// Filtering options
	UserID string `long:"userid"`
	Page   uint32 `long:"page"`
}

// Execute executes the cmdCommentVotes command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentVotes) Execute(args []string) error {
	// Unpack args & filtering options
	var (
		token  = c.Args.Token
		userID = c.UserID
		page   = c.Page
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

	// Print votes or an empty message if no votes were found
	if len(vr.Votes) > 0 {
		printCommentVotes(vr.Votes)
	} else {
		if userID != "" {
			printf("No comment votes found for user %v\n", userID)
		} else {
			printf("No comment votes found for proposal %v\n", token)
		}
	}

	return nil
}

// commentVotesHelpMsg is printed to stdout by the help command.
const commentVotesHelpMsg = `commentvotes "token"

Get paginated comment up/downvotes of a proposal. The --userid flag can be 
used to retrieve the votes of a specific user. The --page flag can be used 
to retrieve a specific page, if no page is provided then the first page is 
returned.

Arguments:
1. token  (string, required)  Proposal censorship token

Flags:
  --userid  (string, optional)  User ID
  --page    (uint32, optional)  Requested page`
