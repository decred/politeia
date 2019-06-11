// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// OpposeDCCCmd allows a user to oppose a DCC proposal.
type OpposeDCCCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the oppose DCC command.
func (cmd *OpposeDCCCmd) Execute(args []string) error {
	token := cmd.Args.Token
	comment := "nay"
	if token == "" {
		return fmt.Errorf("invalid request: you must specify dcc " +
			"token")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}

	// Setup new comment request
	sig := cfg.Identity.SignMessage([]byte(token + comment))

	sd := v1.OpposeDCC{
		Token:     cmd.Args.Token,
		Comment:   comment,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := printJSON(sd)
	if err != nil {
		return err
	}

	// Send request
	sdr, err := client.OpposeDCC(sd)
	if err != nil {
		return fmt.Errorf("OpposeDCC: %v", err)
	}

	// Print response details
	err = printJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
