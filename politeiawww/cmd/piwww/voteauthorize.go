// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// voteAuthorizeCmd authorizes a proposal vote.  The VoteAuthorizeCmd must be
// sent by the proposal author to be valid.
type voteAuthorizeCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"` // Censorship token
		Action string `positional-arg-name:"action"`                // Authorize or revoke action
	} `positional-args:"true"`
}

// Execute executes the authorize vote command.
func (cmd *voteAuthorizeCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Validate action
	var action pi.VoteAuthActionT
	switch cmd.Args.Action {
	case "authorize":
		action = pi.VoteAuthActionAuthorize
	case "revoke":
		action = pi.VoteAuthActionRevoke
	case "":
		// Default to authorize
		action = pi.VoteAuthActionAuthorize
	default:
		return fmt.Errorf("Invalid action.  Valid actions are:\n  " +
			"authorize  (default) authorize a vote\n  " +
			"revoke     revoke a vote authorization")
	}

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get proposal version
	pdr, err := client.ProposalDetails(token, nil)
	if err != nil {
		return err
	}

	// Setup authorize vote request
	sig := cfg.Identity.SignMessage([]byte(token + pdr.Proposal.Version +
		cmd.Args.Action))
	va := pi.VoteAuthorize{
		Action:    action,
		Token:     token,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = shared.PrintJSON(va)
	if err != nil {
		return err
	}

	// Send request
	varep, err := client.VoteAuthorize(va)
	if err != nil {
		return err
	}

	// Validate authorize vote receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(varep.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(va.Signature), s) {
		return fmt.Errorf("could not verify authorize vote receipt")
	}

	// Print response details
	return shared.PrintJSON(vr)
}

// voteAuthorizeHelpMsg is the output of the help command when 'voteauthorize'
// is specified.
const voteAuthorizeHelpMsg = `voteauthorize "token" "action"

Authorize or revoke proposal vote. Only the proposal author (owner of 
censorship token) can authorize or revoke vote. 

Arguments:
1. token      (string, required)   Proposal censorship token
2. action     (string, optional)   Valid actions are 'authorize' or 'revoke'
                                   (defaults to 'authorize')
`
