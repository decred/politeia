// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

var (
	_ plugins.TlogClient = (*Tlog)(nil)
)

// BlobSave saves a BlobEntry to the tlog instance. The BlobEntry will be
// encrypted prior to being written to disk if the tlog instance has an
// encryption key set. The digest of the data, i.e. BlobEntry.Digest, can be
// thought of as the blob ID and can be used to get/del the blob from tlog.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobSave(treeID int64, dataType string, be store.BlobEntry) error {
	log.Tracef("%v BlobSave: %v %v", t.id, treeID, dataType)

	// Verify data type
	if strings.Contains(dataType, dataTypeSeperator) {
		return fmt.Errorf("data type cannot contain '%v'", dataTypeSeperator)
	}

	// Prepare blob and digest
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	blob, err := t.blobify(be)
	if err != nil {
		return err
	}

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Verify tree is not frozen
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll: %v", err)
	}
	if t.treeIsFrozen(leaves) {
		return backend.ErrRecordLocked
	}

	// Save blobs to store
	keys, err := t.store.Put([][]byte{blob})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Prepare log leaf
	extraData := leafExtraData(dataType, keys[0])
	leaves = []*trillian.LogLeaf{
		newLogLeaf(digest, extraData),
	}

	// Append log leaf to trillian tree
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if err != nil {
		return fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queued leaves: "+
			"got %v, want 1", len(queued))
	}
	c := codes.Code(queued[0].QueuedLeaf.GetStatus().GetCode())
	if c != codes.OK {
		return fmt.Errorf("queued leaf error: %v", c)
	}

	return nil
}

// BlobsDel deletes the blobs that correspond to the provided digests.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsDel(treeID int64, digests [][]byte) error {
	log.Tracef("%v BlobsDel: %v %x", t.id, treeID, digests)

	// Verify tree exists. We allow blobs to be deleted from both
	// frozen and non frozen trees.
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Get all tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll: %v", err)
	}

	// Put merkle leaf hashes into a map so that we can tell if a leaf
	// corresponds to one of the target merkle leaf hashes in O(n)
	// time.
	merkleHashes := make(map[string]struct{}, len(leaves))
	for _, v := range digests {
		m := hex.EncodeToString(merkleLeafHash(v))
		merkleHashes[m] = struct{}{}
	}

	// Aggregate the key-value store keys for the provided merkle leaf
	// hashes.
	keys := make([]string, 0, len(digests))
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

// Blobs returns the blobs that correspond to the provided digests. If a blob
// does not exist it will not be included in the returned map.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) Blobs(treeID int64, digests [][]byte) (map[string]store.BlobEntry, error) {
	log.Tracef("%v Blobs: %v %x", t.id, treeID, digests)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Aggregate the leaves that correspond to the provided merkle
	// hashes.
	// map[merkleLeafHash]*trillian.LogLeaf
	leaves := make(map[string]*trillian.LogLeaf, len(digests))
	for _, v := range digests {
		m := hex.EncodeToString(merkleLeafHash(v))
		leaves[m] = nil
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
			return nil, fmt.Errorf("leaf not found: %v", k)
		}
	}

	// Extract the key-value store keys. These keys MUST be put in the
	// same order that the digests were provided in.
	keys := make([]string, 0, len(leaves))
	for _, v := range digests {
		m := hex.EncodeToString(merkleLeafHash(v))
		l, ok := leaves[m]
		if !ok {
			return nil, fmt.Errorf("leaf not found: %x", v)
		}
		keys = append(keys, extractKeyFromLeaf(l))
	}

	// Pull the blobs from the store. It's ok if one or more blobs is
	// not found. It is the responsibility of the caller to decide how
	// this should be handled.
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}

	// Deblob the blobs and put them in a map so the caller can
	// determine if any blob entries are missing.
	entries := make(map[string]store.BlobEntry, len(blobs)) // [digest]BlobEntry
	for k, v := range keys {
		// The digests slice and the keys slice share the same order
		digest := hex.EncodeToString(digests[k])
		b, ok := blobs[v]
		if !ok {
			return nil, fmt.Errorf("blob not found: %v", v)
		}
		be, err := t.deblob(b)
		if err != nil {
			return nil, fmt.Errorf("deblob %v: %v", digest, err)
		}
		entries[digest] = *be
	}

	return entries, nil
}

// BlobsByDataType returns all blobs that match the data type.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) BlobsByDataType(treeID int64, dataType string) ([]store.BlobEntry, error) {
	log.Tracef("%v BlobsByDataType: %v %v", t.id, treeID, dataType)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
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
		if leafDataType(v) == dataType {
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

	// Prepare reply. The blob entries should be in the same order as
	// the keys, i.e. ordered from oldest to newest.
	entries := make([]store.BlobEntry, 0, len(keys))
	for _, v := range keys {
		b, ok := blobs[v]
		if !ok {
			return nil, fmt.Errorf("blob not found: %v", v)
		}
		be, err := t.deblob(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	return entries, nil
}

// DigestsByDataType returns the digests of all blobs that match the data type.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) DigestsByDataType(treeID int64, dataType string) ([][]byte, error) {
	log.Tracef("%v DigestsByDataType: %v %v", t.id, treeID, dataType)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the digests, i.e. the leaf value, of
	// all leaves that match the provided data type.
	digests := make([][]byte, 0, len(leaves))
	for _, v := range leaves {
		if leafDataType(v) == dataType {
			digests = append(digests, v.LeafValue)
		}
	}

	return digests, nil
}

// Timestamp returns the timestamp for the data blob that corresponds to the
// provided digest.
//
// This function satisfies the plugins.TlogClient interface.
func (t *Tlog) Timestamp(treeID int64, digest []byte) (*backend.Timestamp, error) {
	log.Tracef("%v Timestamp: %v %x", t.id, treeID, digest)

	// Get tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Get merkle leaf hash
	m := merkleLeafHash(digest)

	// Get timestamp
	return t.timestamp(treeID, m, leaves)
}
