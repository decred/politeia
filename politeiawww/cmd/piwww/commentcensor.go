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
		Token     string `positional-arg-name:"token"`     // Censorship token
		CommentID string `positional-arg-name:"commentID"` // Comment ID
		Reason    string `positional-arg-name:"reason"`    // Reason for censoring
	} `positional-args:"true" required:"true"`

	// CLI flags
	Vetted   bool `long:"vetted" optional:"true"`
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the censor comment command.
func (cmd *commentCensorCmd) Execute(args []string) error {
	token := cmd.Args.Token
	commentID := cmd.Args.CommentID
	reason := cmd.Args.Reason

	// Verify state
	var state pi.PropStateT
	switch {
	case cmd.Vetted && cmd.Unvetted:
		return fmt.Errorf("cannot use --vetted and --unvetted simultaneously")
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	case cmd.Vetted:
		state = pi.PropStateVetted
	default:
		return fmt.Errorf("must specify either --vetted or unvetted")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Setup comment censor request
	s := cfg.Identity.SignMessage([]byte(string(state) + token + commentID + reason))
	signature := hex.EncodeToString(s[:])
	// Parse provided comment id
	ciUint, err := strconv.ParseUint(commentID, 10, 32)
	if err != nil {
		return err
	}
	cc := pi.CommentCensor{
		Token:     token,
		State:     state,
		CommentID: uint32(ciUint),
		Reason:    reason,
		Signature: signature,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = shared.PrintJSON(cc)
	if err != nil {
		return err
	}

	// Send request
	ccr, err := client.CommentCensor(cc)
	if err != nil {
		return err
	}

	// Validate censor comment receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	receiptB, err := util.ConvertSignature(ccr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), receiptB) {
		return fmt.Errorf("could not verify receipt signature")
	}

	// Print response details
	return shared.PrintJSON(ccr)
}

// commentCensorHelpMsg is the output of the help command when 'commentcensor'
// is specified.
const commentCensorHelpMsg = `commentcensor "token" "commentID" "reason"

Censor a user comment. Requires admin privileges.

Arguments:
1. token       (string, required)   Proposal censorship token
2. commentID   (string, required)   Id of the comment
3. reason      (string, required)   Reason for censoring the comment

Flags:
  --vetted     (bool, optional)    Comment on vetted record.
  --unvetted   (bool, optional)    Comment on unvetted reocrd.
`
