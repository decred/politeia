// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
)

// TreeNew creates a new tlog tree and returns the tree ID.
func (t *Tstore) TreeNew() (int64, error) {
	log.Tracef("TreeNew")

	tree, _, err := t.tlog.TreeNew()
	if err != nil {
		return 0, err
	}

	return tree.TreeId, nil
}

// TreesAll returns the IDs of all trees in the tstore instance.
func (t *Tstore) TreesAll() ([]int64, error) {
	trees, err := t.tlog.TreesAll()
	if err != nil {
		return nil, err
	}
	treeIDs := make([]int64, 0, len(trees))
	for _, v := range trees {
		treeIDs = append(treeIDs, v.TreeId)
	}
	return treeIDs, nil
}

// TreeExists returns whether a tree exists in the trillian log. A tree
// existing doesn't necessarily mean that a record exists. Its possible for a
// tree to have been created but experienced an unexpected error prior to the
// record being saved.
func (t *Tstore) TreeExists(treeID int64) bool {
	_, err := t.tlog.Tree(treeID)
	return err == nil
}

// timestamp returns the timestamp given a tlog tree merkle leaf hash.
func (t *Tstore) timestamp(treeID int64, merkleLeafHash []byte, leaves []*trillian.LogLeaf) (*backend.Timestamp, error) {
	// Find the leaf
	var l *trillian.LogLeaf
	for _, v := range leaves {
		if bytes.Equal(merkleLeafHash, v.MerkleLeafHash) {
			l = v
			break
		}
	}
	if l == nil {
		return nil, fmt.Errorf("leaf not found")
	}

	// Get blob entry from the kv store
	ed, err := extraDataDecode(l.ExtraData)
	if err != nil {
		return nil, err
	}
	blobs, err := t.store.Get([]string{ed.storeKey()})
	if err != nil {
		return nil, fmt.Errorf("store get: %v", err)
	}

	// Extract the data blob. Its possible for the data blob to not
	// exist if it has been censored. This is ok. We'll still return
	// the rest of the timestamp.
	var data []byte
	if len(blobs) == 1 {
		b, ok := blobs[ed.storeKey()]
		if !ok {
			return nil, fmt.Errorf("blob not found %v", ed.storeKey())
		}
		be, err := store.Deblob(b)
		if err != nil {
			return nil, err
		}
		data, err = base64.StdEncoding.DecodeString(be.Data)
		if err != nil {
			return nil, err
		}
		// Sanity check
		if !bytes.Equal(l.LeafValue, util.Digest(data)) {
			return nil, fmt.Errorf("data digest does not match leaf value")
		}
	}

	// Setup timestamp
	ts := backend.Timestamp{
		Data:   string(data),
		Digest: hex.EncodeToString(l.LeafValue),
		Proofs: []backend.Proof{},
	}

	// Get the anchor record for this leaf
	a, err := t.anchorForLeaf(treeID, merkleLeafHash, leaves)
	if err != nil {
		if err == errAnchorNotFound {
			// This data has not been anchored yet
			return &ts, nil
		}
		return nil, fmt.Errorf("anchor: %v", err)
	}

	// Get trillian inclusion proof
	p, err := t.tlog.InclusionProof(treeID, l.MerkleLeafHash, a.LogRoot)
	if err != nil {
		return nil, fmt.Errorf("InclusionProof %v %x: %v",
			treeID, l.MerkleLeafHash, err)
	}

	// Setup proof for data digest inclusion in the log merkle root
	edt := ExtraDataTrillianRFC6962{
		LeafIndex: p.LeafIndex,
		TreeSize:  int64(a.LogRoot.TreeSize),
	}
	extraData, err := json.Marshal(edt)
	if err != nil {
		return nil, err
	}
	merklePath := make([]string, 0, len(p.Hashes))
	for _, v := range p.Hashes {
		merklePath = append(merklePath, hex.EncodeToString(v))
	}
	trillianProof := backend.Proof{
		Type:       ProofTypeTrillianRFC6962,
		Digest:     ts.Digest,
		MerkleRoot: hex.EncodeToString(a.LogRoot.RootHash),
		MerklePath: merklePath,
		ExtraData:  string(extraData),
	}

	// Setup proof for log merkle root inclusion in the dcrtime merkle
	// root
	if a.VerifyDigest.Digest != trillianProof.MerkleRoot {
		return nil, fmt.Errorf("trillian merkle root not anchored")
	}
	var (
		numLeaves = a.VerifyDigest.ChainInformation.MerklePath.NumLeaves
		hashes    = a.VerifyDigest.ChainInformation.MerklePath.Hashes
		flags     = a.VerifyDigest.ChainInformation.MerklePath.Flags
	)
	edd := ExtraDataDcrtime{
		NumLeaves: numLeaves,
		Flags:     base64.StdEncoding.EncodeToString(flags),
	}
	extraData, err = json.Marshal(edd)
	if err != nil {
		return nil, err
	}
	merklePath = make([]string, 0, len(hashes))
	for _, v := range hashes {
		merklePath = append(merklePath, hex.EncodeToString(v[:]))
	}
	dcrtimeProof := backend.Proof{
		Type:       ProofTypeDcrtime,
		Digest:     a.VerifyDigest.Digest,
		MerkleRoot: a.VerifyDigest.ChainInformation.MerkleRoot,
		MerklePath: merklePath,
		ExtraData:  string(extraData),
	}

	// Update timestamp
	ts.TxID = a.VerifyDigest.ChainInformation.Transaction
	ts.MerkleRoot = a.VerifyDigest.ChainInformation.MerkleRoot
	ts.Proofs = []backend.Proof{
		trillianProof,
		dcrtimeProof,
	}

	// Verify timestamp
	err = VerifyTimestamp(ts)
	if err != nil {
		return nil, fmt.Errorf("VerifyTimestamp: %v", err)
	}

	return &ts, nil
}
