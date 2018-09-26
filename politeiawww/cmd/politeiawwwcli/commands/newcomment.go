package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

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
