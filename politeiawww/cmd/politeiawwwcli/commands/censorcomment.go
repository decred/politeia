package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

// Help message displayed for the command 'politeiawwwcli help censorcomment'
var CensorCommentCmdHelpMsg = `censorcomment "token" "commentID" "reason"

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

type CensorCommentCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token" description:"Proposal censorship token"`
		CommentID string `positional-arg-name:"commentID" description:"ID of the comment"`
		Reason    string `positional-arg-name:"reason" description:"Reason for censoring the comment"`
	} `positional-args:"true" required:"true"`
}

func (cmd *CensorCommentCmd) Execute(args []string) error {
	token := cmd.Args.Token
	commentID := cmd.Args.CommentID
	reason := cmd.Args.Reason

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Get server public key
	vr, err := c.Version()
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
	err = Print(cc, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	ccr, err := c.CensorComment(cc)
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
	return Print(ccr, cfg.Verbose, cfg.RawJSON)
}
