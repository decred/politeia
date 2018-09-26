package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type VoteCommentCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID string `positional-arg-name:"commentID"`
		Action    string `positional-arg-name:"action"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VoteCommentCmd) Execute(args []string) error {
	token := cmd.Args.Token
	commentID := cmd.Args.CommentID
	action := cmd.Args.Action

	// Validate action
	if action != "downvote" && action != "upvote" {
		return fmt.Errorf("invalid action %s; the action must be either "+
			"downvote or upvote", action)
	}

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Setup like comment request
	var actionCode string
	switch action {
	case "upvote":
		actionCode = "1"
	case "downvote":
		actionCode = "-1"
	}

	sig := cfg.Identity.SignMessage([]byte(token + commentID + actionCode))
	lc := &v1.LikeComment{
		Token:     token,
		CommentID: commentID,
		Action:    actionCode,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := Print(lc, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	lcr, err := c.LikeComment(lc)
	if err != nil {
		return err
	}

	// Print response details
	return Print(lcr, cfg.Verbose, cfg.RawJSON)
}
