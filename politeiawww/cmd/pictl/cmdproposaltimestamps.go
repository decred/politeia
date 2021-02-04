// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposalTimestamps retrieves the timestamps for a politeiawww proposal.
type cmdProposalTimestamps struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Version string `positional-arg-name:"version" optional:"true"`
	} `positional-args:"true"`

	// Unvetted is used to request the timestamps of an unvetted
	// proposal. If this flag is not used it will be assume that the
	// proposal is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdProposalTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalTimestamps) Execute(args []string) error {
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
		state = piv1.ProposalStateUnvetted
	default:
		state = piv1.ProposalStateVetted
	}

	// Get timestamps
	t := rcv1.Timestamps{
		State:   state,
		Token:   c.Args.Token,
		Version: c.Args.Version,
	}
	tr, err := pc.RecordTimestamps(t)
	if err != nil {
		return err
	}

	// Verify timestamps
	err = verifyTimestamp(tr.RecordMetadata)
	if err != nil {
		return fmt.Errorf("verify proposal metadata timestamp: %v", err)
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

	// Print timestamps
	printJSON(tr)

	return nil
}

func verifyTimestamp(t rcv1.Timestamp) error {
	ts := convertTimestamp(t)
	return tlog.VerifyTimestamp(ts)
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

// proposalTimestampsHelpMsg is printed to stdout by the help command.
const proposalTimestampsHelpMsg = `proposaltimestamps [flags] "token" "version"

Fetch the timestamps a proposal version. The timestamp contains all necessary
data to verify that user submitted proposal data has been timestamped onto the
decred blockchain.

This command defaults to requesting vetted proposals unless the --unvetted flag
is used.

Arguments:
1. token    (string, required) Record token
2. version  (string, optional) Record version

Flags:
 --unvetted (bool, optional)   Request is for unvetted proposals.
`
