// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// cmdCommentNew submits a new comment.
type cmdCommentNew struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`
		Comment  string `positional-arg-name:"comment" required:"true"`
		ParentID uint32 `positional-arg-name:"parentid"`
	} `positional-args:"true"`

	// Unvetted is used to comment on an unvetted record. If this flag
	// is not used the command assumes the record is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`

	// UpdateTitle is used to post a new author update.
	UpdateTitle string `long:"updatetitle" optional:"true"`
}

// Execute executes the cmdCommentNew command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentNew) Execute(args []string) error {
	// Unpack args
	var (
		token    = c.Args.Token
		comment  = c.Args.Comment
		parentID = c.Args.ParentID
	)

	// Check for user identity. A user identity is required to sign
	// the comment.
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

	// Setup state
	var state cmv1.RecordStateT
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
	}

	// Prepare extra data if it's a new author update
	var (
		extraData,
		extraDataHint string
	)
	if c.UpdateTitle != "" {
		extraDataHint = piv1.ProposalUpdateHint
		pum := piv1.ProposalUpdateMetadata{
			Title: c.UpdateTitle,
		}
		b, err := json.Marshal(pum)
		if err != nil {
			return err
		}
		extraData = string(b)
	}

	// Setup request
	msg := strconv.FormatUint(uint64(state), 10) + token +
		strconv.FormatUint(uint64(parentID), 10) + comment +
		extraData + extraDataHint
	sig := cfg.Identity.SignMessage([]byte(msg))
	n := cmv1.New{
		State:         state,
		Token:         token,
		ParentID:      parentID,
		Comment:       comment,
		Signature:     hex.EncodeToString(sig[:]),
		PublicKey:     cfg.Identity.Public.String(),
		ExtraDataHint: extraDataHint,
		ExtraData:     extraData,
	}

	// Send request
	nr, err := pc.CommentNew(n)
	if err != nil {
		return err
	}

	// Verify receipt
	vr, err := client.Version()
	if err != nil {
		return err
	}
	err = pclient.CommentVerify(nr.Comment, vr.PubKey)
	if err != nil {
		return err
	}

	// Print receipt
	printComment(nr.Comment)

	return nil
}

// commentNewHelpMsg is printed to stdout by the help command.
const commentNewHelpMsg = `commentnew "token" "comment" parentid

Comment on a record. Requires the user to be logged in.

This command assumes the record is a vetted record.

If the record is unvetted, the --unvetted flag must be used. Commenting on
unvetted records requires admin priviledges.

Proposal's author may post author update using the --updatetitle flag. Author 
updates are allowed only on a proposal which finished voting and it's
vote was approved. User can reply only on the latest author update. When a 
proposal billing status is set to closed or completed it's not possible to 
post author updates or to reply on them.

Arguments:
1. token     (string, required)  Proposal censorship token.
2. comment   (string, required)  Comment text.
3. parentid  (uint32, optional)  ID of parent commment. Including a parent ID
                                 indicates that the comment is a reply.

Flags:
  --unvetted    (bool, optional)   Record is unvetted.
  --updatetitle (string, optional) Authour update title.
`
