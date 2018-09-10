package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

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

	// Get user identity.
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}
	id := config.UserIdentity

	// Create signature.
	s := id.SignMessage([]byte(token + commentID + reason))
	signature := hex.EncodeToString(s[:])
	publicKey := hex.EncodeToString(id.Public.Key[:])

	// Send censor comment request.
	ccr, err := Ctx.CensorComment(token, commentID, reason, signature, publicKey)
	if err != nil {
		return err
	}

	// Get server public key.
	vr, err := Ctx.Version()
	if err != nil {
		return err
	}

	// Validate censor comment receipt.
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

	return nil
}
