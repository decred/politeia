// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/util"
)

// CensorCommentCmd censors a proposal comment.
type CensorCommentCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`     // Censorship token
		CommentID string `positional-arg-name:"commentID"` // Comment ID
		Reason    string `positional-arg-name:"reason"`    // Reason for censoring
	} `positional-args:"true" required:"true"`
}

// Execute executes the censor comment command.
func (cmd *CensorCommentCmd) Execute(args []string) error {
	token := cmd.Args.Token
	commentID := cmd.Args.CommentID
	reason := cmd.Args.Reason

	// Check for user identity
	if cfg.Identity == nil {
		return ErrUserIdentityNotFound
	}

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Setup censor comment request
	s := cfg.Identity.SignMessage([]byte(token + commentID + reason))
	signature := hex.EncodeToString(s[:])
	cc := &v1.CensorComment{
		Token:     token,
		CommentID: commentID,
		Reason:    reason,
		Signature: signature,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = PrintJSON(cc)
	if err != nil {
		return err
	}

	// Send request
	ccr, err := client.CensorComment(cc)
	if err != nil {
		return err
	}

	// Validate censor comment receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	receiptB, err := util.ConvertSignature(ccr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), receiptB) {
		return fmt.Errorf("could not verify receipt signature")
	}

	// Print response details
	return PrintJSON(ccr)
}

// CensorCommentHelpMsg is the output of the help command when 'censorcomment'
// is specified.
const CensorCommentHelpMsg = `censorcomment "token" "commentID" "reason"

Censor a user comment. Requires admin privileges.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentID   (string, required)   Id of the comment
3. reason      (string, required)   Reason for censoring the comment

Request:
{
  "token":      (string)  Censorship token
  "commentid":  (string)  Id of comment
  "reason":     (string)  Reason for censoring the comment
  "signature":  (string)  Signature of censor comment (Token+CommentID+Reason)
  "publickey":  (string)  Public key used for signature
}

Response:
{
  "receipt":  (string)  Server signature of comment sensor signature
}`
