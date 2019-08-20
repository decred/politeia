// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
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
		return errUserIdentityNotFound
	}

	sd := v1.SupportOpposeDCC{
		Vote:  vote,
		Token: token,
	}

	// Print request details
	err := printJSON(sd)
	if err != nil {
		return err
	}

	// Send request
	sdr, err := client.SupportOpposeDCC(sd)
	if err != nil {
		return fmt.Errorf("SupportOpposeDCC: %v", err)
	}

	// Print response details
	err = printJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
