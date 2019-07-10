// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/tlog/api/v1"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

// RecordEntryNew returns an encoded tlog RecordEntry structure.
func RecordEntryNew(myId *identity.FullIdentity, dataHint, data []byte) v1.RecordEntry {
	// Calculate hash
	h := sha256.New()
	h.Write(data)

	// Create record
	re := v1.RecordEntry{
		Hash:     hex.EncodeToString(h.Sum(nil)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}

	// XXX don't sign when we don't have an identity. This is not
	// acceptable and only a temporary workaround until trillian properly
	// supports ed25519.
	if myId != nil {
		re.PublicKey = hex.EncodeToString(myId.Public.Key[:])

		// Sign
		signature := myId.SignMessage([]byte(re.Hash))
		re.Signature = hex.EncodeToString(signature[:])
	}

	return re
}

// RecordEntryVerify ensures that a tlog RecordEntry is valid.
func RecordEntryVerify(record v1.RecordEntry) error {
	// Decode identity
	id, err := IdentityFromString(record.PublicKey)
	if err != nil {
		return err
	}

	// Decode hash
	hash, err := hex.DecodeString(record.Hash)
	if err != nil {
		return err
	}

	// Decode signature
	s, err := hex.DecodeString(record.Signature)
	if err != nil {
		return err
	}
	var signature [64]byte
	copy(signature[:], s)

	// Decode data
	data, err := base64.StdEncoding.DecodeString(record.Data)
	if err != nil {
		return err
	}
	// Verify hash
	h := sha256.New()
	h.Write(data)
	if !bytes.Equal(hash, h.Sum(nil)) {
		return fmt.Errorf("invalid hash")
	}

	// Verify signature
	if !id.VerifyMessage([]byte(record.Hash), signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// QueuedLeafProof ensures that a queued leaf and the inclusion proof for the
// leaf are valid.
func QueuedLeafProofVerify(pk crypto.PublicKey, lrv1 *types.LogRootV1, qlp v1.QueuedLeafProof) error {
	// Check queued leaf status
	c := codes.Code(qlp.QueuedLeaf.GetStatus().GetCode())
	if c != codes.OK {
		return fmt.Errorf("queued leaf status: %v",
			qlp.QueuedLeaf.GetStatus().GetMessage())
	}

	// Verify inclusion proof. A queued log leaf does not have
	// a leaf index so this must be done using the leaf hash.
	lh, err := hashers.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		return err
	}
	verifier := client.NewLogVerifier(lh, pk, crypto.SHA256)
	err = verifier.VerifyInclusionByHash(lrv1,
		qlp.QueuedLeaf.Leaf.MerkleLeafHash, qlp.Proof)
	if err != nil {
		return fmt.Errorf("VerifyInclusionByHash: %v", err)
	}

	return nil
}

// RecordEntryProofVerify ensures that a RecordEntry and the inclusion proof
// for the RecordEntry anchor is valid.
func RecordEntryProofVerify(pk crypto.PublicKey, rep v1.RecordEntryProof) error {
	if rep.Error != "" {
		return fmt.Errorf("%v", rep.Error)
	}

	// Verify record
	err := RecordEntryVerify(*rep.RecordEntry)
	if err != nil {
		return fmt.Errorf("RecordEntryVerify: %v", err)
	}

	if rep.Anchor == nil {
		// If an achor does not exist then
		// there is nothing else to verify.
		return nil
	}

	// Verify STH
	lrv1, err := tcrypto.VerifySignedLogRoot(pk, crypto.SHA256, rep.STH)
	if err != nil {
		return fmt.Errorf("VerifySignedLogRoot: %v", err)
	}

	// Verify inclusion proof
	lh, err := hashers.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		return err
	}

	verifier := client.NewLogVerifier(lh, pk, crypto.SHA256)
	err = verifier.VerifyInclusionAtIndex(lrv1,
		rep.Leaf.LeafValue, rep.Leaf.LeafIndex,
		rep.Proof.Hashes)
	if err != nil {
		return fmt.Errorf("VerifyInclusionAtIndex: %v", err)
	}

	// Also verify by hash
	err = verifier.VerifyInclusionByHash(lrv1,
		rep.Leaf.MerkleLeafHash, rep.Proof)
	if err != nil {
		return fmt.Errorf("VerifyInclusionByHash: %v", err)
	}

	// XXX Verify anchor merkle path

	return nil
}
