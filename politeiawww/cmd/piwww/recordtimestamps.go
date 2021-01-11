// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// recordTimestampsCmd retrieves the timestamps for a politeiawww record.
type recordTimestampsCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Version string `positional-arg-name:"version" optional:"true"`
	} `positional-args:"true"`

	// Unvetted is used to request the timestamps of an unvetted
	// record.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the recordTimestampsCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *recordTimestampsCmd) Execute(args []string) error {

	// Set record state. Defaults to vetted unless the unvetted flag
	// is used.
	var state rcv1.StateT
	switch {
	case c.Unvetted:
		state = rcv1.StateUnvetted
	default:
		state = rcv1.StateVetted
	}

	// Setup request
	t := rcv1.Timestamps{
		State:   state,
		Token:   c.Args.Token,
		Version: c.Args.Version,
	}

	// Send request
	err := shared.PrintJSON(t)
	if err != nil {
		return err
	}
	tr, err := client.RecordTimestamps(t)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(tr)
	if err != nil {
		return err
	}

	// Verify timestamps
	err = verifyTimestamp(tr.RecordMetadata)
	if err != nil {
		return fmt.Errorf("verify record metadata timestamp: %v", err)
	}
	for k, v := range tr.Metadata {
		err = verifyTimestamp(v)
		if err != nil {
			return fmt.Errorf("verify metadata %v timestamp: %v", k, err)
		}
	}
	for k, v := range tr.Files {
		err = verifyTimestamp(v)
		if err != nil {
			return fmt.Errorf("verify file %v timestamp: %v", k, err)
		}
	}

	return nil
}

func verifyTimestamp(t rcv1.Timestamp) error {
	ts := convertTimestamp(t)
	return tlogbe.VerifyTimestamp(ts)
}

func convertProof(p rcv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestamp(t rcv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

// recordTimestampsHelpMsg is the output of the help command.
const recordTimestampsHelpMsg = `recordtimestamps [flags] "token" "version"

Fetch the timestamps a record version. The timestamp contains all necessary
data to verify that user submitted record data has been timestamped onto the
decred blockchain.

Arguments:
1. token   (string, required) Proposal token
2. version (string, optional) Proposal version

Flags:
 --unvetted     (bool, optional) Request is for unvetted records instead of
																 vetted ones (default: false).
`
