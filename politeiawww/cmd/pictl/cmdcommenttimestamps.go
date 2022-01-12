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

	// If given comment IDs is empty fetch all IDs and request timestamps
	// page by page.
	commentIDs := c.Args.CommentIDs
	if len(commentIDs) == 0 {
		// Fetch all comments
		cm := cmv1.Comments{
			Token: c.Args.Token,
		}
		cmr, err := pc.Comments(cm)
		if err != nil {
			return err
		}

		// Collect comment IDs
		for _, c := range cmr.Comments {
			commentIDs = append(commentIDs, c.CommentID)
		}
	}

	// If the proposal has no comments yet, nothing to do.
	if len(commentIDs) == 0 {
		printf("Proposal has no comments \n")
		return nil
	}

	// Get timestamps page size
	pr, err := pc.CommentPolicy()
	if err != nil {
		return err
	}
	pageSize := pr.TimestampsPageSize

	// Timestamps route is paginated, request timestamps page by page.
	var (
		pageStartIdx int
		fetched      int
	)
	for pageStartIdx < len(commentIDs) {
		pageEndIdx := pageStartIdx + int(pageSize)
		if pageEndIdx > len(commentIDs) {
			// We've reached the end of the slice
			pageEndIdx = len(commentIDs)
		}

		// pageStartIdx is included. pageEndIdx is excluded.
		page := commentIDs[pageStartIdx:pageEndIdx]

		// Get timestamps
		t := cmv1.Timestamps{
			Token:      c.Args.Token,
			CommentIDs: page,
		}
		tr, err := pc.CommentTimestamps(t)
		if err != nil {
			return err
		}
		fetched = fetched + len(page)

		// Verify timestamps
		notTimestamped, err := pclient.CommentTimestampsVerify(*tr)
		if err != nil {
			return err
		}
		if len(notTimestamped) > 0 {
			printf("Not timestamped yet: %v\n", notTimestamped)
		}

		printf("Fetched timestampes of %v/%v comments \n", fetched,
			len(commentIDs))

		// Next page start index
		pageStartIdx = pageEndIdx
	}

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
