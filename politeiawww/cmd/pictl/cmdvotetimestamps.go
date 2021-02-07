// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// cmdVoteTimestamps retrieves the timestamps for a politeiawww ticket vote.
type cmdVoteTimestamps struct {
	Args struct {
		Token string `positional-arg-name:"token" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdVoteTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTimestamps) Execute(args []string) error {
	/*
		// Setup request
		t := tkv1.Timestamps{
			Token: c.Args.Token,
		}

		// Send request
		err := shared.PrintJSON(t)
		if err != nil {
			return err
		}
		tr, err := client.TicketVoteTimestamps(t)
		if err != nil {
			return err
		}
		err = shared.PrintJSON(tr)
		if err != nil {
			return err
		}

		// Verify timestamps
		for k, v := range tr.Auths {
			err = verifyVoteTimestamp(v)
			if err != nil {
				return fmt.Errorf("verify authorization %v timestamp: %v", k, err)
			}
		}
		err = verifyVoteTimestamp(tr.Details)
		if err != nil {
			return fmt.Errorf("verify vote details timestamp: %v", err)
		}
		for k, v := range tr.Votes {
			err = verifyVoteTimestamp(v)
			if err != nil {
				return fmt.Errorf("verify vote %v timestamp: %v", k, err)
			}
		}
	*/

	return nil
}

func verifyVoteTimestamp(t tkv1.Timestamp) error {
	ts := convertVoteTimestamp(t)
	return tlog.VerifyTimestamp(ts)
}

func convertVoteProof(p tkv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertVoteTimestamp(t tkv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertVoteProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

// voteTimestampsHelpMsg is printed to stdout by the help command.
const voteTimestampsHelpMsg = `votetimestamps "token"

Fetch the timestamps for a ticket vote. This includes timestamps for all
authorizations, the vote details, and all cast votes.

Arguments:
1. token   (string, required) Record token
`
