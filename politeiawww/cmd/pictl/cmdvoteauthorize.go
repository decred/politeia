// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdVoteAuthorize authorizes a ticket vote or revokes a previous
// authorization.
type cmdVoteAuthorize struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Action  string `positional-arg-name:"action"`
		Version uint32 `positional-arg-name:"version"`
	} `positional-args:"true"`
}

// Execute executes the cmdVoteAuthorize command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteAuthorize) Execute(args []string) error {
	// Verify action
	var action tkv1.AuthActionT
	switch c.Args.Action {
	case "authorize":
		action = tkv1.AuthActionAuthorize
	case "revoke":
		action = tkv1.AuthActionRevoke
	case "":
		// Default to authorize
		action = tkv1.AuthActionAuthorize
	default:
		return fmt.Errorf("Invalid action; \n%v", voteAuthorizeHelpMsg)
	}

	// Verify user identity. An identity is required to sign the vote
	// authorization.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Get record version
	version := c.Args.Version
	if version == 0 {
		d := rcv1.Details{
			State: rcv1.RecordStateVetted,
			Token: c.Args.Token,
		}
		r, err := pc.RecordDetails(d)
		if err != nil {
			return err
		}
		u, err := strconv.ParseUint(r.Version, 10, 64)
		if err != nil {
			return err
		}
		version = uint32(u)
	}

	// Setup request
	msg := c.Args.Token + strconv.FormatUint(uint64(version), 10) +
		string(action)
	sig := cfg.Identity.SignMessage([]byte(msg))
	a := tkv1.Authorize{
		Token:     c.Args.Token,
		Version:   version,
		Action:    action,
		PublicKey: cfg.Identity.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Send request
	ar, err := pc.TicketVoteAuthorize(a)
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
	if !serverID.VerifyMessage([]byte(a.Signature), s) {
		return fmt.Errorf("could not verify receipt")
	}

	// Print receipt
	printf("Token    : %v\n", a.Token)
	printf("Action   : %v\n", a.Action)
	printf("Timestamp: %v\n", timestampFromUnix(ar.Timestamp))
	printf("Receipt  : %v\n", ar.Receipt)

	return nil
}

// voteAuthorizeHelpMsg is printed to stdout by the help command.
const voteAuthorizeHelpMsg = `voteauthorize "token" "action"

Authorize or revoke a ticket vote.

If an action is not provided this command defaults to authorizing a ticket
vote. The user must be the record author.

Valid actions:
  authorize  authorize a vote
  revoke     revoke a previous authorization

Arguments:
1. token    (string, required)  Record token.
2. action   (string, optional)  Authorize vote action.`
