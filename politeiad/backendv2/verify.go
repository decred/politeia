// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backendv2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/dcrtime/merkle"
	dmerkle "github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	tmerkle "github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers/registry"
	_ "github.com/google/trillian/merkle/rfc6962"
)

const (
	// ProofTypeTrillianRFC6962 represents a trillian proof that uses
	// the trillian hashing strategy HashStrategy_RFC6962_SHA256.
	ProofTypeTrillianRFC6962 = "trillian-rfc6962"

	// ProofTypeDcrtime represents a dcrtime proof.
	ProofTypeDcrtime = "dcrtime"
)

// ExtraDataTrillianRFC6962 contains the extra data required to verify a
// trillian inclusion proof.
type ExtraDataTrillianRFC6962 struct {
	LeafIndex int64 `json:"leafindex"`
	TreeSize  int64 `json:"treesize"`
}

// verifyProofTrillian verifies a proof with the type ProofTypeTrillianRFC6962.
func verifyProofTrillian(p Proof) error {
	// Verify type
	if p.Type != ProofTypeTrillianRFC6962 {
		return fmt.Errorf("invalid proof type")
	}

	// The digest of the data is stored in trillian as the leaf value.
	// The digest of the leaf value is the digest that is included in
	// the log merkle root.
	h, err := registry.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		return err
	}
	leafValue, err := hex.DecodeString(p.Digest)
	if err != nil {
		return err
	}
	leafHash := h.HashLeaf(leafValue)

	merkleRoot, err := hex.DecodeString(p.MerkleRoot)
	if err != nil {
		return err
	}

	merklePath := make([][]byte, 0, len(p.MerklePath))
	for _, v := range p.MerklePath {
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		merklePath = append(merklePath, b)
	}

	var ed ExtraDataTrillianRFC6962
	err = json.Unmarshal([]byte(p.ExtraData), &ed)
	if err != nil {
		return err
	}

	verifier := tmerkle.NewLogVerifier(h)
	return verifier.VerifyInclusionProof(ed.LeafIndex, ed.TreeSize,
		merklePath, merkleRoot, leafHash)
}

// ExtraDataDcrtime contains the extra data required to verify a dcrtime
// inclusion proof.
type ExtraDataDcrtime struct {
	NumLeaves uint32 // Nuber of leaves
	Flags     string // Bitmap of merkle tree, base64 encoded
}

// verifyProofDcrtime verifies a proof with the type ProofTypeDcrtime.
func verifyProofDcrtime(p Proof) error {
	if p.Type != ProofTypeDcrtime {
		return fmt.Errorf("invalid proof type")
	}

	// Verify digest is part of merkle path
	var found bool
	for _, v := range p.MerklePath {
		if v == p.Digest {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("digest %v not found in merkle path %v",
			p.Digest, p.MerklePath)
	}

	// Decode extra data
	var ed ExtraDataDcrtime
	err := json.Unmarshal([]byte(p.ExtraData), &ed)
	if err != nil {
		return err
	}
	flags, err := base64.StdEncoding.DecodeString(ed.Flags)
	if err != nil {
		return err
	}

	// Calculate merkle root
	digests := make([][sha256.Size]byte, 0, len(p.MerklePath))
	for _, v := range p.MerklePath {
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		var d [sha256.Size]byte
		copy(d[:], b)
		digests = append(digests, d)
	}
	mb := merkle.Branch{
		NumLeaves: ed.NumLeaves,
		Hashes:    digests,
		Flags:     flags,
	}
	mr, err := dmerkle.VerifyAuthPath(&mb)
	if err != nil {
		return err
	}
	merkleRoot := hex.EncodeToString(mr[:])

	// Verify merkle root matches
	if merkleRoot != p.MerkleRoot {
		return fmt.Errorf("invalid merkle root: got %v, want %v",
			merkleRoot, p.MerkleRoot)
	}

	return nil
}

// verifyProof verifies a backend proof.
func verifyProof(p Proof) error {
	switch p.Type {
	case ProofTypeTrillianRFC6962:
		return verifyProofTrillian(p)
	case ProofTypeDcrtime:
		return verifyProofDcrtime(p)
	}
	return fmt.Errorf("invalid proof type")
}

var (
	// ErrNotTimestamped is returned when a timestamp does not contain
	// a TxID. This indicates that the data has yet to be included in
	// a DCR transaction.
	ErrNotTimestamped = errors.New("data has not be included in a dcr tx yet")
)

// VerifyTimestamp verifies the inclusion of the data in the merkle root that
// was timestamped onto the dcr blockchain.
func VerifyTimestamp(t Timestamp) error {
	if t.TxID == "" {
		return ErrNotTimestamped
	}

	// Verify digest. The data blob may not be included in certain
	// scenerios such as if it has been censored.
	if t.Data != "" {
		d := hex.EncodeToString(util.Digest([]byte(t.Data)))
		if d != t.Digest {
			return fmt.Errorf("invalid digest: got %v, want %v", d, t.Digest)
		}
	}

	// Verify proof ordering. The digest of the first proof should be
	// the data digest. The digest of every subsequent proof should be
	// the merkle root of the previous proof.
	if len(t.Proofs) == 0 {
		return fmt.Errorf("no proofs found")
	}
	if t.Digest != t.Proofs[0].Digest {
		return fmt.Errorf("invalid proofs: digest %v not found", t.Digest)
	}
	nextDigest := t.Proofs[0].MerkleRoot
	for i := 1; i < len(t.Proofs); i++ {
		p := t.Proofs[i]
		if p.Digest != nextDigest {
			return fmt.Errorf("invalid proof %v digest: got %v, want %v",
				i, p.Digest, nextDigest)
		}
		nextDigest = t.MerkleRoot
	}

	// Verify the merkle root of the last proof is the merkle root
	// that was included in the dcr transaction.
	if nextDigest != t.MerkleRoot {
		return fmt.Errorf("merkle root of last proof does not match timestamped "+
			"merkle root: got %v, want %v", nextDigest, t.MerkleRoot)
	}

	// Verify proofs
	for _, v := range t.Proofs {
		err := verifyProof(v)
		if err != nil {
			return fmt.Errorf("invalid %v proof: %v", v.Type, err)
		}
	}

	return nil
}
