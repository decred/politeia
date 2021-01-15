// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

// BlobsSave saves the provided blobs to the tlog backend. Note, hashes
// contains the hashes of the data encoded in the blobs. The hashes must share
// the same ordering as the blobs.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsSave(treeID int64, keyPrefix string, blobs, hashes [][]byte) ([][]byte, error) {
	log.Tracef("%v BlobsSave: %v %v", t.id, treeID, keyPrefix)

	// Sanity check
	if len(blobs) != len(hashes) {
		return nil, fmt.Errorf("blob count and hashes count mismatch: "+
			"got %v blobs, %v hashes", len(blobs), len(hashes))
	}

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, ErrRecordNotFound
	}

	// Verify tree is not frozen
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}
	idx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return nil, err
	}
	if idx.Frozen {
		return nil, ErrTreeIsFrozen
	}

	// Encrypt blobs if an encryption key has been set
	if t.encryptionKey != nil {
		for k, v := range blobs {
			e, err := t.encrypt(v)
			if err != nil {
				return nil, err
			}
			blobs[k] = e
		}
	}

	// Save blobs to store
	keys, err := t.store.Put(blobs)
	if err != nil {
		return nil, fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != len(blobs) {
		return nil, fmt.Errorf("wrong number of keys: got %v, want %v",
			len(keys), len(blobs))
	}

	// Prepare log leaves. hashes and keys share the same ordering.
	leaves := make([]*trillian.LogLeaf, 0, len(blobs))
	for k := range blobs {
		pk := []byte(keyPrefix + keys[k])
		leaves = append(leaves, newLogLeaf(hashes[k], pk))
	}

	// Append leaves to trillian tree
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if err != nil {
		return nil, fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != len(leaves) {
		return nil, fmt.Errorf("wrong number of queued leaves: got %v, want %v",
			len(queued), len(leaves))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("append leaves failed: %v", failed)
	}

	// Parse and return the merkle leaf hashes
	merkles := make([][]byte, 0, len(blobs))
	for _, v := range queued {
		merkles = append(merkles, v.QueuedLeaf.Leaf.MerkleLeafHash)
	}

	return merkles, nil
}

// BlobsDel deletes the blobs in the kv store that correspond to the provided
// merkle leaf hashes. The kv store keys in store in the ExtraData field of the
// leaves specified by the provided merkle leaf hashes.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsDel(treeID int64, merkles [][]byte) error {
	log.Tracef("%v BlobsDel: %v", t.id, treeID)

	// Verify tree exists. We allow blobs to be deleted from both
	// frozen and non frozen trees.
	if !t.TreeExists(treeID) {
		return ErrRecordNotFound
	}

	// Get all tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return err
	}

	// Put merkle leaf hashes into a map so that we can tell if a leaf
	// corresponds to one of the target merkle leaf hashes in O(n)
	// time.
	merkleHashes := make(map[string]struct{}, len(leaves))
	for _, v := range merkles {
		merkleHashes[hex.EncodeToString(v)] = struct{}{}
	}

	// Aggregate the key-value store keys for the provided merkle leaf
	// hashes.
	keys := make([]string, 0, len(merkles))
	for _, v := range leaves {
		_, ok := merkleHashes[hex.EncodeToString(v.MerkleLeafHash)]
		if ok {
			keys = append(keys, extractKeyFromLeaf(v))
		}
	}

	// Delete file blobs from the store
	err = t.store.Del(keys)
	if err != nil {
		return fmt.Errorf("store Del: %v", err)
	}

	return nil
}

// BlobsByMerkle returns the blobs with the provided merkle leaf hashes.
//
// If a blob does not exist it will not be included in the returned map. It is
// the responsibility of the caller to check that a blob is returned for each
// of the provided merkle hashes.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsByMerkle(treeID int64, merkles [][]byte) (map[string][]byte, error) {
	log.Tracef("%v BlobsByMerkle: %v", t.id, treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, ErrRecordNotFound
	}

	// Get leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Aggregate the leaves that correspond to the provided merkle
	// hashes.
	// map[merkleHash]*trillian.LogLeaf
	leaves := make(map[string]*trillian.LogLeaf, len(merkles))
	for _, v := range merkles {
		leaves[hex.EncodeToString(v)] = nil
	}
	for _, v := range leavesAll {
		m := hex.EncodeToString(v.MerkleLeafHash)
		if _, ok := leaves[m]; ok {
			leaves[m] = v
		}
	}

	// Ensure a leaf was found for all provided merkle hashes
	for k, v := range leaves {
		if v == nil {
			return nil, fmt.Errorf("leaf not found for merkle hash: %v", k)
		}
	}

	// Extract the key-value store keys. These keys MUST be put in the
	// same order that the merkle hashes were provided in.
	keys := make([]string, 0, len(leaves))
	for _, v := range merkles {
		l, ok := leaves[hex.EncodeToString(v)]
		if !ok {
			return nil, fmt.Errorf("leaf not found for merkle hash: %x", v)
		}
		keys = append(keys, extractKeyFromLeaf(l))
	}

	// Pull the blobs from the store. If is ok if one or more blobs is
	// not found. It is the responsibility of the caller to decide how
	// this should be handled.
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}

	// Decrypt any encrypted blobs
	for k, v := range blobs {
		if blobIsEncrypted(v) {
			b, _, err := t.encryptionKey.decrypt(v)
			if err != nil {
				return nil, err
			}
			blobs[k] = b
		}
	}

	// Put blobs in a map so the caller can determine if any of the
	// provided merkle hashes did not correspond to a blob in the
	// store.
	b := make(map[string][]byte, len(blobs)) // [merkleHash]blob
	for k, v := range keys {
		// The merkle hashes slice and keys slice share the same order
		merkleHash := hex.EncodeToString(merkles[k])
		blob, ok := blobs[v]
		if !ok {
			return nil, fmt.Errorf("blob not found for key %v", v)
		}
		b[merkleHash] = blob
	}

	return b, nil
}

// BlobsByKeyPrefix returns all blobs that match the provided key prefix.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error) {
	log.Tracef("%v BlobsByKeyPrefix: %v %v", t.id, treeID, keyPrefix)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, ErrRecordNotFound
	}

	// Get leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the key-value store keys for all
	// leaves with a matching key prefix.
	keys := make([]string, 0, len(leaves))
	for _, v := range leaves {
		if bytes.HasPrefix(v.ExtraData, []byte(keyPrefix)) {
			keys = append(keys, extractKeyFromLeaf(v))
		}
	}

	// Pull the blobs from the store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != len(keys) {
		// One or more blobs were not found
		missing := make([]string, 0, len(keys))
		for _, v := range keys {
			_, ok := blobs[v]
			if !ok {
				missing = append(missing, v)
			}
		}
		return nil, fmt.Errorf("blobs not found: %v", missing)
	}

	// Decrypt any encrypted blobs
	for k, v := range blobs {
		if blobIsEncrypted(v) {
			b, _, err := t.encryptionKey.decrypt(v)
			if err != nil {
				return nil, err
			}
			blobs[k] = b
		}
	}

	// Covert blobs from map to slice
	b := make([][]byte, 0, len(blobs))
	for _, v := range blobs {
		b = append(b, v)
	}

	return b, nil
}

// MerklesByKeyPrefix returns the merkle leaf hashes for all blobs that match
// the key prefix.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) MerklesByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error) {
	log.Tracef("%v MerklesByKeyPrefix: %v %v", t.id, treeID, keyPrefix)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, ErrRecordNotFound
	}

	// Get leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the merkle leaf hashes with a matching
	// key prefix.
	merkles := make([][]byte, 0, len(leaves))
	for _, v := range leaves {
		if bytes.HasPrefix(v.ExtraData, []byte(keyPrefix)) {
			merkles = append(merkles, v.MerkleLeafHash)
		}
	}

	return merkles, nil
}

// Timestamp returns the timestamp for the data blob that corresponds to the
// provided merkle leaf hash.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) Timestamp(treeID int64, merkleLeafHash []byte) (*backend.Timestamp, error) {
	log.Tracef("%v Timestamp: %v %x", t.id, treeID, merkleLeafHash)

	// Get all tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Get timestamp
	return t.timestamp(treeID, merkleLeafHash, leaves)
}
