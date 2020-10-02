// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	utilwww "github.com/decred/politeia/politeiawww/util"
)

// signedMerkleRoot calculates the merkle root of the passed in list of files
// and metadata, signs the merkle root with the passed in identity and returns
// the signature.
func signedMerkleRoot(files []pi.File, md []pi.Metadata, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := utilwww.MerkleRoot(files, md)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// convertTicketHashes converts a slice of hexadecimal ticket hashes into
// a slice of byte slices.
func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	return hashes, nil
}

// proposalRecord returns the ProposalRecord for the provided token and
// version.
func proposalRecord(state pi.PropStateT, token, version string) (*pi.ProposalRecord, error) {
	ps := pi.Proposals{
		State: state,
		Requests: []pi.ProposalRequest{
			{
				Token:   token,
				Version: version,
			},
		},
		IncludeFiles: true,
	}
	psr, err := client.Proposals(ps)
	if err != nil {
		return nil, err
	}
	pr, ok := psr.Proposals[token]
	if !ok {
		return nil, fmt.Errorf("proposal not found")
	}

	return &pr, nil
}

// proposalRecord returns the latest ProposalRecrord version for the provided
// token.
func proposalRecordLatest(state pi.PropStateT, token string) (*pi.ProposalRecord, error) {
	return proposalRecord(state, token, "")
}

// decodeProposalMetadata decodes and returns a ProposalMetadata given the
// metadata array from a ProposalRecord.
func decodeProposalMetadata(metadata []pi.Metadata) (*pi.ProposalMetadata, error) {
	var pm *pi.ProposalMetadata
	for _, v := range metadata {
		if v.Hint == pi.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(b, pm)
			if err != nil {
				return nil, err
			}
		}
	}
	if pm == nil {
		return nil, fmt.Errorf("proposal metadata not found")
	}
	return pm, nil
}
