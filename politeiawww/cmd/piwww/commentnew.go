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

// commentNewCmd submits a new proposal comment.
type commentNewCmd struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`
		Comment  string `positional-arg-name:"comment" required:"true"`
		ParentID string `positional-arg-name:"parentid"`
	} `positional-args:"true"`

	// CLI flags
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the new comment command.
func (c *commentNewCmd) Execute(args []string) error {
	// Unpack args
	token := c.Args.Token
	comment := c.Args.Comment

	var parentID uint64
	var err error
	if c.Args.ParentID == "" {
		parentID = 0
	} else {
		parentID, err = strconv.ParseUint(c.Args.ParentID, 10, 32)
		if err != nil {
			return fmt.Errorf("ParseUint(%v): %v", c.Args.ParentID, err)
		}
	}

	// Verify identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Verify state. Defaults to vetted if the --unvetted flag
	// is not used.
	var state pi.PropStateT
	switch {
	case c.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
	}

	// Sign comment data
	msg := strconv.Itoa(int(state)) + token +
		strconv.FormatUint(parentID, 10) + comment
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])

	// Setup request
	cn := pi.CommentNew{
		Token:     token,
		State:     state,
		ParentID:  uint32(parentID),
		Comment:   comment,
		Signature: signature,
		PublicKey: cfg.Identity.Public.String(),
	}

	// Send request. The request and response details are printed to
	// the console.
	err = shared.PrintJSON(cn)
	if err != nil {
		return err
	}
	cnr, err := client.CommentNew(cn)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(cnr)
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
	receiptb, err := util.ConvertSignature(cnr.Comment.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(signature), receiptb) {
		return fmt.Errorf("could not verify receipt")
	}

	return nil
}

// commentNewHelpMsg is the help command message.
const commentNewHelpMsg = `commentnew "token" "comment" "parentid"

Comment on a record as logged in user. This command assumes the record is a
vetted record. If the record is unvetted, the --unvetted flag must be used.
Requires admin priviledges.

Arguments:
1. token       (string, required)  Proposal censorship token
2. comment     (string, required)  Comment
3. parentid    (string, optional)  ID of parent commment. Including a parent ID
                                   indicates that the comment is a reply.

Flags:
  --unvetted   (bool, optional)    Comment on unvetted record.
`
