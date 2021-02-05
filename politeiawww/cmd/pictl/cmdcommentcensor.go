// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdCommentCensor censors a proposal comment.
type cmdCommentCensor struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID uint32 `positional-arg-name:"commentid"`
		Reason    string `positional-arg-name:"reason"`
	} `positional-args:"true" required:"true"`

	// Unvetted is used to censor the comment on an unvetted record. If
	// this flag is not used the command assumes the record is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdCommentCensor command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentCensor) Execute(args []string) error {
	// Unpack args
	var (
		token     = c.Args.Token
		commentID = c.Args.CommentID
		reason    = c.Args.Reason
	)

	// Check for user identity. A user identity is required to sign
	// the censor request.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup state
	var state string
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
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

	// Setup request
	msg := token + strconv.FormatUint(uint64(commentID), 10) + reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	d := cmv1.Del{
		State:     state,
		Token:     token,
		CommentID: uint32(commentID),
		Reason:    reason,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: cfg.Identity.Public.String(),
	}

	// Send request
	dr, err := pc.CommentDel(d)
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
	receiptb, err := util.ConvertSignature(dr.Comment.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(d.Signature), receiptb) {
		return fmt.Errorf("could not verify receipt")
	}

	// Print comment
	printComment(dr.Comment)

	return nil
}

// commentCensorHelpMsg is printed to stdout by the help command.
const commentCensorHelpMsg = `commentcensor "token" "commentID" "reason"

Censor a comment.

If the record is unvetted, the --unvetted flag must be used. This command
requires admin priviledges.

Arguments:
1. token      (string, required)  Proposal censorship token
2. commentid  (string, required)  ID of the comment
3. reason     (string, required)  Reason for censoring the comment

Flags:
  --unvetted  (bool, optional)  Record is unvetted.
`
