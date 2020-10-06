// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	utilwww "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
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

// verifyDigests verifies if the list of files and metadatas have valid
// digests. It compares digests that came with the file/metadata with
// digests calculated from their payload.
func verifyDigests(files []pi.File, md []pi.Metadata) error {
	// Validate file digests
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return fmt.Errorf("file: %v decode payload err %v",
				f.Name, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return fmt.Errorf("file: %v invalid digest %v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return fmt.Errorf("file: %v digests do not match",
				f.Name)
		}
	}

	// Validate metadata digests
	for _, v := range md {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return fmt.Errorf("metadata: %v decode payload err %v",
				v.Hint, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return fmt.Errorf("metadata: %v invalid digest %v",
				v.Hint, v.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return fmt.Errorf("metadata: %v digests do not match metadata",
				v.Hint)
		}
	}

	return nil
}

// verifyProposal verifies the merkle root, author signature and censorship
// record of a given proposal.
func verifyProposal(p pi.ProposalRecord, serverPubKey string) error {
	if len(p.Files) > 0 {
		// Verify digests
		err := verifyDigests(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		// Verify merkle root
		mr, err := utilwww.MerkleRoot(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		// Check if merkle roots match
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("invalid proposal signature")
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("invalid censorship record signature")
	}

	return nil
}
