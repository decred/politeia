// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/thi4go/politeia/decredplugin"
	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
	"github.com/thi4go/politeia/util"
)

// AuthorizeVoteCmd authorizes a proposal vote.  The AuthorizeVoteCmd must be
// sent by the proposal author to be valid.
type AuthorizeVoteCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"` // Censorship token
		Action string `positional-arg-name:"action"`                // Authorize or revoke action
	} `positional-args:"true"`
}

// Execute executes the authorize vote command.
func (cmd *AuthorizeVoteCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Validate action
	switch cmd.Args.Action {
	case decredplugin.AuthVoteActionAuthorize,
		decredplugin.AuthVoteActionRevoke:
		// This is correct; continue
	case "":
		// Default to authorize
		cmd.Args.Action = decredplugin.AuthVoteActionAuthorize
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
	av := &v1.AuthorizeVote{
		Action:    cmd.Args.Action,
		Token:     token,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = shared.PrintJSON(av)
	if err != nil {
		return err
	}

	// Send request
	avr, err := client.AuthorizeVote(av)
	if err != nil {
		return err
	}

	// Validate authorize vote receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(avr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(av.Signature), s) {
		return fmt.Errorf("could not verify authorize vote receipt")
	}

	// Print response details
	return shared.PrintJSON(avr)
}

// authorizeVoteHelpMsg is the output of the help command when 'authorizevote'
// is specified.
const authorizeVoteHelpMsg = `authorizevote "token" "action"

Authorize or revoke proposal vote. Only the proposal author (owner of 
censorship token) can authorize or revoke vote. 

Arguments:
1. token      (string, required)   Proposal censorship token
2. action     (string, optional)   Valid actions are 'authorize' or 'revoke'
                                   (defaults to 'authorize')

Result:
{
  "action":    (string)  Action that was executed
  "receipt":   (string)  Server signature of client signature 
                         (signed token+version+action)
}`
