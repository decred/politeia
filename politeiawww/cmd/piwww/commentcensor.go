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

// commentCensorCmd censors a proposal comment.
type commentCensorCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID string `positional-arg-name:"commentid"`
		Reason    string `positional-arg-name:"reason"`
	} `positional-args:"true" required:"true"`

	// CLI flags
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the censor comment command.
func (cmd *commentCensorCmd) Execute(args []string) error {
	// Unpack args
	token := cmd.Args.Token
	reason := cmd.Args.Reason
	commentID, err := strconv.ParseUint(cmd.Args.CommentID, 10, 32)
	if err != nil {
		return fmt.Errorf("ParseUint(%v): %v", cmd.Args.CommentID, err)
	}

	// Verify user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Verify state. Defaults to vetted if the --unvetted flag
	// is not used.
	var state pi.PropStateT
	switch {
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
	}

	// Sign comment data
	msg := strconv.Itoa(int(state)) + token + cmd.Args.CommentID + reason
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])

	// Setup request
	cc := pi.CommentCensor{
		Token:     token,
		State:     state,
		CommentID: uint32(commentID),
		Reason:    reason,
		Signature: signature,
		PublicKey: cfg.Identity.Public.String(),
	}

	// Send request. The request and response details are printed to
	// the console.
	err = shared.PrintJSON(cc)
	if err != nil {
		return err
	}
	ccr, err := client.CommentCensor(cc)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(ccr)
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
	receiptb, err := util.ConvertSignature(ccr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), receiptb) {
		return fmt.Errorf("could not verify receipt")
	}

	return nil
}

// commentCensorHelpMsg is the help command message.
const commentCensorHelpMsg = `commentcensor "token" "commentID" "reason"

Censor a user comment. This command assumes the record is a vetted record. If
the record is unvetted, the --unvetted flag must be used. Requires admin 
privileges.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentid   (string, required)   ID of the comment
3. reason      (string, required)   Reason for censoring the comment

Flags:
  --unvetted   (bool, optional)    Comment on unvetted record.
`
