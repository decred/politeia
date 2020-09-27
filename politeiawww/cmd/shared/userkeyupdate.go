// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// UserKeyUpdateCmd creates a new identity for the logged in user.
type UserKeyUpdateCmd struct {
	NoSave bool `long:"nosave"` // Don't save new identity to disk
}

// Execute executes the update user key command.
func (cmd *UserKeyUpdateCmd) Execute(args []string) error {
	// Get the logged in user's username. We need
	// this when we save the new identity to disk.
	me, err := client.Me()
	if err != nil {
		return fmt.Errorf("Me: %v", err)
	}

	// Create new identity
	id, err := NewIdentity()
	if err != nil {
		return err
	}

	// Update user key
	uuk := &v1.UpdateUserKey{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	err = PrintJSON(uuk)
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
	return PrintJSON(vuukr)
}

// UserKeyUpdateHelpMsg is the output of the help command when 'userkeyupdate'
// is specified.
const UserKeyUpdateHelpMsg = `userkeyupdate

Generate a new public key for the currently logged in user. 

Arguments:
None`
