// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/cmsplugin"
	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// VoteDCCCmd allows a user to vote for a DCC proposal during an all contractor vote.
type VoteDCCCmd struct {
	Args struct {
		Vote  string `positional-arg-name:"vote"`
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the support DCC command.
func (cmd *VoteDCCCmd) Execute(args []string) error {
	token := cmd.Args.Token
	vote := cmd.Args.Vote

	if vote != cmsplugin.DCCApprovalString && vote != cmsplugin.DCCDisapprovalString {
		return fmt.Errorf("invalid request: you must either vote yes or no")
	}

	if token == "" {
		return fmt.Errorf("invalid request: you must specify dcc " +
			"token")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	sig := cfg.Identity.SignMessage([]byte(token + vote))
	sd := v1.VoteDCC{
		Vote:      vote,
		Token:     token,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err := shared.PrintJSON(sd)
	if err != nil {
		return err
	}

	// Send request
	sdr, err := client.VoteDCC(sd)
	if err != nil {
		return fmt.Errorf("VoteDCC: %v", err)
	}

	// Print response details
	err = shared.PrintJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
