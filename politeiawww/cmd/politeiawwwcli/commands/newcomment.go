// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help newcomment'
var NewCommentCmdHelpMsg = `newcomment "token" "comment"

Comment on proposal as logged in user. 

Arguments:
1. token       (string, required)   Proposal censorship token
2. comment     (string, required)   Comment
3. parentID    (string, required if replying to comment)  Id of commment

Request:
{
  "token":       (string)  Censorship token
  "parentid":    (string)  Id of comment (defaults to '0' (top-level comment))
  "comment":     (string)  Comment
  "signature":   (string)  Signature of comment (token+parentID+comment)
  "publickey":   (string)  Public key of user commenting
}

Response:
{
  "comment": {
    "token":        (string)  Censorship token
    "parentid":     (string)  Id of comment (defaults to '0' (top-level))
    "comment":      (string)  Comment
    "signature":    (string)  Signature of token+parentID+comment
    "publickey":    (string)  Public key of user 
    "commentid":    (string)  Id of the comment
    "receipt":      (string)  Server signature of the comment signature
    "timestamp":    (int64)   Received UNIX timestamp
    "totalvotes":   (uint64)  Total number of up/down votes
    "resultvotes":  (int64)   Vote score
    "censored":     (bool)    If comment has been censored
    "userid":       (string)  User id
    "username":     (string)  Username
  }
}`

type NewCommentCmd struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`
		Comment  string `positional-arg-name:"comment" required:"true"`
		ParentID string `positional-arg-name:"parentID"`
	} `positional-args:"true"`
}

func (cmd *NewCommentCmd) Execute(args []string) error {
	token := cmd.Args.Token
	comment := cmd.Args.Comment
	parentID := cmd.Args.ParentID

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Setup new comment request
	sig := cfg.Identity.SignMessage([]byte(token + parentID + comment))
	nc := &v1.NewComment{
		Token:     token,
		ParentID:  parentID,
		Comment:   comment,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := Print(nc, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	ncr, err := c.NewComment(nc)
	if err != nil {
		return err
	}

	// Print response details
	return Print(ncr, cfg.Verbose, cfg.RawJSON)
}
