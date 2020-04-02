// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// SupportOpposeDCCCmd allows a user to support a DCC proposal.
type SupportOpposeDCCCmd struct {
	Args struct {
		Vote  string `positional-arg-name:"vote"`
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the support DCC command.
func (cmd *SupportOpposeDCCCmd) Execute(args []string) error {
	token := cmd.Args.Token
	vote := cmd.Args.Vote

	if vote != "aye" && vote != "nay" {
		return fmt.Errorf("invalid request: you must either vote aye or nay")
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
	sd := v1.SupportOpposeDCC{
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
	sdr, err := client.SupportOpposeDCC(sd)
	if err != nil {
		return fmt.Errorf("SupportOpposeDCC: %v", err)
	}

	// Print response details
	err = shared.PrintJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
