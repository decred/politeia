package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type VerifyUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email" description:"User email address"`
		Token string `positional-arg-name:"token" description:"Email verification token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VerifyUserCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Verify new user
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token))
	vnur, err := c.VerifyNewUser(&v1.VerifyNewUser{
		Email:             cmd.Args.Email,
		VerificationToken: cmd.Args.Token,
		Signature:         hex.EncodeToString(sig[:]),
	})
	if err != nil {
		return err
	}

	// Print response details
	return Print(vnur, cfg.Verbose, cfg.RawJSON)
}
