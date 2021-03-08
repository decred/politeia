// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentTimestamps retrieves the timestamps for a record's comments.
type cmdCommentTimestamps struct {
	Args struct {
		Token      string   `positional-arg-name:"token" required:"true"`
		CommentIDs []uint32 `positional-arg-name:"commentids" optional:"true"`
	} `positional-args:"true"`

	// Unvetted is used to request the timestamps of an unvetted
	// record. If this flag is not used the command assumes the record
	// is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdCommentTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentTimestamps) Execute(args []string) error {
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
	var state string
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
	}

	// Get timestamps
	t := cmv1.Timestamps{
		State:      state,
		Token:      c.Args.Token,
		CommentIDs: c.Args.CommentIDs,
	}
	tr, err := pc.CommentTimestamps(t)
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
	return tstore.VerifyTimestamp(ts)
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

// commentTimestampsHelpMsg is printed to stdout by the help command.
const commentTimestampsHelpMsg = `commenttimestamps [flags] "token" commentIDs

Fetch the timestamps for a record's comments. The timestamp contains all
necessary data to verify that user submitted comment data has been timestamped
onto the decred blockchain.

If comment IDs are not provided then the timestamps for all comments will be
returned. If the record is unvetted, the --unvetted flag must be used.

Arguments:
1. token      (string, required)   Proposal token
2. commentIDs ([]uint32, optional) Proposal version

Flags:
  --unvetted  (bool, optional)  Record is unvetted.

Example: Fetch all record comment timestamps
$ pictl commenttimestamps 0a265dd93e9bae6d 

Example: Fetch comment timestamps for comment IDs 1, 6, and 7
$ pictl commenttimestamps 0a265dd93e9bae6d  1 6 7`
