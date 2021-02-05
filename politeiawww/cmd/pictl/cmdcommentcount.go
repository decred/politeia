// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentCount retreives the comments for the specified proposal.
type cmdCommentCount struct {
	Args struct {
		Tokens []string `positional-arg-name:"tokens"`
	} `positional-args:"true" required:"true"`

	// Unvetted is used to request the comment counts of unvetted
	// records. If this flag is not used the command assumes the
	// records are vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdCommentCount command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentCount) Execute(args []string) error {
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

	// Setup state
	var state string
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
	}

	// Get comments
	cc := cmv1.Count{
		State:  state,
		Tokens: c.Args.Tokens,
	}
	cr, err := pc.CommentCount(cc)
	if err != nil {
		return err
	}

	// Print counts
	for k, v := range cr.Counts {
		fmt.Printf("%v %v\n", k, v)
	}

	return nil
}

// commentCountHelpMsg is printed to stdout by the help command.
const commentCountHelpMsg = `commentcount "tokens..." 

Get the number of comments that have been made on each of the provided
records.

If the record is unvetted, the --unvetted flag must be used. This command
accepts both full length tokens or the token prefixes.

Arguments:
1. token  (string, required)  Proposal censorship token

Flags:
  --unvetted  (bool, optional)  Record is unvetted.

Examples:
$ pictl commentcount f6458c2d8d9ef41c 9f9af91cf609d839 917c6fde9bcc2118
$ pictl commentcount f6458c2 9f9af91 917c6fd`
