package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// UpdateUserKeyCmd creates a new identity for the logged in user.
type UpdateUserKeyCmd struct {
	NoSave bool `long:"nosave"` // Don't save new identity to disk
}

// Execute executes the update user key command.
func (cmd *UpdateUserKeyCmd) Execute(args []string) error {
	// Get the logged in user's username. We need
	// this when we save the new identity to disk.
	me, err := client.Me()
	if err != nil {
		return fmt.Errorf("Me: %v", err)
	}

	// Create new identity
	id, err := newIdentity()
	if err != nil {
		return err
	}

	// Update user key
	uuk := &v1.UpdateUserKey{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	err = printJSON(uuk)
	if err != nil {
		return err
	}

	uukr, err := client.UpdateUserKey(uuk)
	if err != nil {
		return fmt.Errorf("UpdateUserKey: %v", err)
	}

	// Verify update user key
	sig := id.SignMessage([]byte(uukr.VerificationToken))
	vuuk := &v1.VerifyUpdateUserKey{
		VerificationToken: uukr.VerificationToken,
		Signature:         hex.EncodeToString(sig[:]),
	}

	vuukr, err := client.VerifyUpdateUserKey(vuuk)
	if err != nil {
		return fmt.Errorf("VerifyUpdateUserKey: %v", err)
	}

	// Save the new identity to disk
	if !cmd.NoSave {
		return cfg.SaveIdentity(me.Username, id)
	}

	// Print response details
	return printJSON(vuukr)
}

// updateUserKeyHelpMsg is the output of the help command when 'updateuserkey'
// is specified.
const updateUserKeyHelpMsg = `updateuserkey

Generate a new public key for the currently logged in user. 

Arguments:
None

Result:
{
  "publickey"   (string)  User's public key
}
{}`
