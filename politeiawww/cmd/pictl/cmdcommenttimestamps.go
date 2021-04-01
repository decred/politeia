// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentTimestamps retrieves the timestamps for a record's comments.
type cmdCommentTimestamps struct {
	Args struct {
		Token      string   `positional-arg-name:"token" required:"true"`
		CommentIDs []uint32 `positional-arg-name:"commentids" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdCommentTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentTimestamps) Execute(args []string) error {
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

	// Get timestamps
	t := cmv1.Timestamps{
		Token:      c.Args.Token,
		CommentIDs: c.Args.CommentIDs,
	}
	tr, err := pc.CommentTimestamps(t)
	if err != nil {
		return err
	}

	// Verify timestamps
	notTimestamped, err := pclient.CommentTimestampsVerify(*tr)
	if err != nil {
		return err
	}

	printf("Not timestamped yet: %v", notTimestamped)
	return nil
}

// commentTimestampsHelpMsg is printed to stdout by the help command.
const commentTimestampsHelpMsg = `commenttimestamps [flags] "token" commentIDs

Fetch the timestamps for a record's comments. The timestamp contains all
necessary data to verify that user submitted comment data has been timestamped
onto the decred blockchain.

If comment IDs are not provided then the timestamps for all comments will be
returned. If the record is unvetted, the --unvetted flag must be used.

Arguments:
1. token      (string, required)   Proposal token
2. commentIDs ([]uint32, optional) Proposal version

Example: Fetch all record comment timestamps
$ pictl commenttimestamps 0a265dd93e9bae6d 

Example: Fetch comment timestamps for comment IDs 1, 6, and 7
$ pictl commenttimestamps 0a265dd93e9bae6d  1 6 7`
