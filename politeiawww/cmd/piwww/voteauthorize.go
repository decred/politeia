// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// voteAuthorizeCmd authorizes a proposal vote or revokes a previous vote
// authorization.
type voteAuthorizeCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		Action string `positional-arg-name:"action"`
	} `positional-args:"true"`
}

// Execute executes the vote authorize command.
func (cmd *voteAuthorizeCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Verify user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Verify action
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
		return fmt.Errorf("Invalid action; \n%v", voteAuthorizeHelpMsg)
	}

	// Get proposal version
	pr, err := proposalRecordLatest(pi.PropStateVetted, token)
	if err != nil {
		return fmt.Errorf("proposalRecordLatest: %v", err)
	}
	// Parse version
	version, err := strconv.ParseUint(pr.Version, 10, 32)
	if err != nil {
		return err
	}

	// Setup request
	msg := token + pr.Version + string(action)
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])
	va := pi.VoteAuthorize{
		Token:     token,
		Version:   uint32(version),
		Action:    action,
		PublicKey: cfg.Identity.Public.String(),
		Signature: signature,
	}

	// Send request. The request and response details are printed to
	// the console.
	err = shared.PrintJSON(va)
	if err != nil {
		return err
	}
	ar, err := client.VoteAuthorize(va)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(ar)
	if err != nil {
		return err
	}

	// Verify receipt
	vr, err := client.Version()
	if err != nil {
		return err
	}
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(ar.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), s) {
		return fmt.Errorf("could not verify receipt")
	}

	return nil
}

// voteAuthorizeHelpMsg is the help command message.
const voteAuthorizeHelpMsg = `voteauthorize "token" "action"

Authorize or revoke a proposal vote. Must be proposal author.

Valid actions:
  authorize  authorize a vote
  revoke     revoke a previous authorization

Arguments:
1. token      (string, required)   Proposal censorship token
2. action     (string, optional)   Authorize vote actions (default: authorize)
`
