// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// BatchProposalsCmd retrieves a set of proposals.
type BatchProposalsCmd struct{}

// Execute executes the batch proposals command.
func (cmd *BatchProposalsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get proposals
	bpr, err := client.BatchProposals(&v1.BatchProposals{
		Tokens: args,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range bpr.Proposals {
		err = verifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print proposals
	return shared.PrintJSON(bpr)
}

// batchProposalsHelpMsg is the output for the help command when
// 'batchproposals' is specified.
const batchProposalsHelpMsg = `batchproposals

Fetch a list of proposals.

Example:
batchproposals token1 token2

Result:
{
  "proposals": [
    {
    "name":          (string)  Suggested short proposal name 
    "state":         (PropStateT)  Current state of proposal
    "status":        (PropStatusT)  Current status of proposal
    "timestamp":     (int64)  Timestamp of last update of proposal
    "userid":        (string)  ID of user who submitted proposal
    "username":      (string)  Username of user who submitted proposal
    "publickey":     (string)  Public key used to sign proposal
    "signature":     (string)  Signature of merkle root
    "files": [],
    "numcomments":   (uint)  Number of comments on the proposal
    "version": 		 (string)  Version of proposal
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of proposal
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
      }
    }
  ]
}`

func merkleRoot(files []v1.File, md []v1.Metadata) (string, error) {
	digests := make([]*[sha256.Size]byte, 0, len(files))

	// Calculate file digests
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", err
		}
		digest := util.Digest(b)
		var hf [sha256.Size]byte
		copy(hf[:], digest)
		digests = append(digests, &hf)
	}

	// Calculate metadata digests
	for _, v := range md {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return "", err
		}
		digest := util.Digest(b)
		var hv [sha256.Size]byte
		copy(hv[:], digest)
		digests = append(digests, &hv)
	}

	// Return merkle root
	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// validateDigests receives a list of files and metadata to verify their
// digests. It compares digests that came with the file/md with digests
// calculated from their respective payloads.
func validateDigests(files []v1.File, md []v1.Metadata) error {
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

// verifyProposal verifies a proposal's merkle root, author signature, and
// censorship record.
func verifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	if len(p.Files) > 0 {
		// Verify digests
		err := validateDigests(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		// Verify merkle root
		mr, err := merkleRoot(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := identity.PublicIdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature
	id, err := identity.PublicIdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
}
