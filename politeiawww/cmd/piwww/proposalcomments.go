// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// ProposalCommentsCmd retreives the comments for the specified proposal.
type ProposalCommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the proposal comments command.
func (cmd *ProposalCommentsCmd) Execute(args []string) error {
	gcr, err := client.GetComments(cmd.Args.Token)
	if err != nil {
		return err
	}
	return shared.PrintJSON(gcr)
}

// proposalCommentsHelpMsg is the output for the help command when
// 'proposalcomments' is specified.
const proposalCommentsHelpMsg = `proposalcomments "token" 

Get the comments for a proposal.

Arguments:
1. token       (string, required)   Proposal censorship token

Result:
{
  "comments": [
    {
      "token":        (string)  Censorship token
      "parentid":     (string)  Id of comment (defaults to '0' (top-level))
      "comment":      (string)  Comment
      "signature":    (string)  Signature of token+parentID+comment
      "publickey":    (string)  Public key of user 
      "commentid":    (string)  Id of the comment
      "receipt":      (string)  Server signature of the comment signature
      "timestamp":    (int64)   Received UNIX timestamp
      "resultvotes":  (int64)   Vote score
      "upvotes":      (uint64)  Pro votes
      "downvotes":    (uint64)  Contra votes
      "censored":     (bool)    If comment has been censored
      "userid":       (string)  User id
      "username":     (string)  Username
    }
  ]
}`
