// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// DCCCommentsCmd retreives the comments for the specified dcc.
type DCCCommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the invoice comments command.
func (cmd *DCCCommentsCmd) Execute(args []string) error {
	gcr, err := client.DCCComments(cmd.Args.Token)
	if err != nil {
		return err
	}
	return shared.PrintJSON(gcr)
}

// dccCommentsHelpMsg is the output for the help command when
// 'dcccomments' is specified.
const dccCommentsHelpMsg = `dcccomments "token" 

Get the comments for a invoice.

Arguments:
1. token       (string, required)   DCC censorship token

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
      "censored":     (bool)    If comment has been censored
      "userid":       (string)  User id
      "username":     (string)  Username
    }
  ]
}`
