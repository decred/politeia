// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"encoding/hex"
	"github.com/thi4go/politeia/politeiawww/api/www/v1"
)

// NewCommentCmd submits a new proposal comment.
type NewCommentCmd struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`   // Censorship token
		Comment  string `positional-arg-name:"comment" required:"true"` // Comment text
		ParentID string `positional-arg-name:"parentID"`                // Comment parent ID
	} `positional-args:"true"`
}

// Execute executes the new comment command.
func (cmd *NewCommentCmd) Execute(args []string) error {
	token := cmd.Args.Token
	comment := cmd.Args.Comment
	parentID := cmd.Args.ParentID

	// Check for user identity
	if cfg.Identity == nil {
		return ErrUserIdentityNotFound
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
	err := PrintJSON(nc)
	if err != nil {
		return err
	}

	// Send request
	ncr, err := client.NewComment(nc)
	if err != nil {
		return err
	}

	// Print response details
	return PrintJSON(ncr)
}

// NewCommentHelpMsg is the output of the help command when 'newcomment' is
// specified.
const NewCommentHelpMsg = `newcomment "token" "comment"

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
    "resultvotes":  (int64)   Vote score
    "upvotes":      (uint64)  Pro votes
    "downvotes":    (uint64)  Contra votes
    "censored":     (bool)    If comment has been censored
    "userid":       (string)  User id
    "username":     (string)  Username
  }
}`
