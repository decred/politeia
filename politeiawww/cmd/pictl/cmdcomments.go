// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdComments retreives the comments for the specified proposal.
type cmdComments struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`

	// CLI flags
	Unvetted bool `long:"unvetted" optional:"true"`
}

/*
// Execute executes the cmdComments command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *cmdComments) Execute(args []string) error {
	token := cmd.Args.Token

	// Verify state. Defaults to vetted if the --unvetted flag
	// is not used.
	var state pi.PropStateT
	switch {
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
	}

	gcr, err := client.Comments(pi.Comments{
		Token: token,
		State: state,
	})
	if err != nil {
		return err
	}

	return shared.PrintJSON(gcr)
}
*/

// commentsHelpMsg is printed to stdout by the help command.
const commentsHelpMsg = `comments "token" 

Get the comments for a record. This command assumes the record is a vetted
record. If the record is unvetted, the --unvetted flag must be used. Requires
admin priviledges.

Arguments:
1. token       (string, required)   Proposal censorship token

Flags:
  --unvetted (bool, optional)    Comment on unvetted record.
`
