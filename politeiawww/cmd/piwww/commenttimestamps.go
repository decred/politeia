// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// commentTimestampsCmd retrieves the timestamps for politeiawww comments.
type commentTimestampsCmd struct {
	Args struct {
		Token      string   `positional-arg-name:"token" required:"true"`
		CommentIDs []uint32 `positional-arg-name:"commentids" optional:"true"`
	} `positional-args:"true"`

	// Unvetted is used to request the comment timestamps of an
	// unvetted record.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the commentTimestampsCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *commentTimestampsCmd) Execute(args []string) error {

	// Set comment state. Defaults to vetted unless the unvetted flag
	// is used.
	var state cmv1.RecordStateT
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
	}

	// Setup request
	t := cmv1.Timestamps{
		State:      state,
		Token:      c.Args.Token,
		CommentIDs: c.Args.CommentIDs,
	}

	// Send request
	err := shared.PrintJSON(t)
	if err != nil {
		return err
	}
	tr, err := client.CommentTimestamps(t)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(tr)
	if err != nil {
		return err
	}

	// Verify timestamps
	for commentID, timestamps := range tr.Comments {
		for _, v := range timestamps {
			err = verifyCommentTimestamp(v)
			if err != nil {
				return fmt.Errorf("verify comment timestamp %v: %v",
					commentID, err)
			}
		}
	}

	return nil
}

func verifyCommentTimestamp(t cmv1.Timestamp) error {
	ts := convertCommentTimestamp(t)
	return tlogbe.VerifyTimestamp(ts)
}

func convertCommentProof(p cmv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertCommentTimestamp(t cmv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertCommentProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

const commentTimestampsHelpMsg = `commenttimestamps [flags] "token" commentIDs

Fetch the timestamps for a record's comments. The timestamp contains all
necessary data to verify that user submitted comment data has been timestamped
onto the decred blockchain.

Arguments:
1. token      (string, required)   Proposal token
2. commentIDs ([]uint32, optional) Proposal version

Flags:
 --unvetted (bool, optional)     Request is for an unvetted record instead of
                                 vetted ones.

Example: Fetch all record comment timestamps
$ piwww commenttimestamps 0a265dd93e9bae6d 

Example: Fetch comment timestamps for comment IDs 1, 6, and 7
$ piwww commenttimestamps 0a265dd93e9bae6d  1 6 7
`
