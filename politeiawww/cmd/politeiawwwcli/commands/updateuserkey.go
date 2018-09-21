package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type UpdateUserKeyCmd struct {
	NoSave bool `long:"nosave" optional:"true" description:"Do not save the user identity to disk"`
}

func (cmd *UpdateUserKeyCmd) Execute(args []string) error {
	// Create new identity
	id, err := NewIdentity()
	if err != nil {
		return err
	}

	// Update user key
	uuk := &v1.UpdateUserKey{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	err = Print(uuk, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	uukr, err := c.UpdateUserKey(uuk)
	if err != nil {
		return fmt.Errorf("UpdateUserKey: %v", err)
	}

	// Verify update user key
	sig := id.SignMessage([]byte(uukr.VerificationToken))
	vuuk := &v1.VerifyUpdateUserKey{
		VerificationToken: uukr.VerificationToken,
		Signature:         hex.EncodeToString(sig[:]),
	}

	vuukr, err := c.VerifyUpdateUserKey(vuuk)
	if err != nil {
		return fmt.Errorf("VerifyUpdateUserKey: %v", err)
	}

	err = Print(vuukr, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Save the new identity to disk
	if !cmd.NoSave {
		cfg.SaveIdentity(id)
	}

	return nil
}
