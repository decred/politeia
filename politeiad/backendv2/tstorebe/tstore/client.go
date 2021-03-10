// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

// BlobSave saves a BlobEntry to the tstore instance. The BlobEntry will be
// encrypted prior to being written to disk if the tstore instance has an
// encryption key set. The digest of the data, i.e. BlobEntry.Digest, can be
// thought of as the blob ID and can be used to get/del the blob from tstore.
//
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) BlobSave(treeID int64, be store.BlobEntry) error {
	log.Tracef("BlobSave: %v", treeID)

	// Parse the data descriptor
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return err
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return err
	}

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Verify tree is not frozen
	leaves, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll: %v", err)
	}
	idx, err := t.recordIndexLatest(leaves)
	if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	if idx.Frozen {
		// The tree is frozen. The record is locked.
		return backend.ErrRecordLocked
	}

	// Prepare blob and digest
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	encrypt := true
	if idx.State == backend.StateVetted {
		// Vetted data is not encrypted
		encrypt = false
	}
	blob, err := t.blobify(be, encrypt)
	if err != nil {
		return err
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
	extraData, err := extraDataEncode(keys[0], dd.Descriptor, encrypt)
	if err != nil {
		return err
	}
	leaves = []*trillian.LogLeaf{
		newLogLeaf(digest, extraData),
	}

	// Append log leaf to trillian tree
	queued, _, err := t.tlog.leavesAppend(treeID, leaves)
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
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) BlobsDel(treeID int64, digests [][]byte) error {
	log.Tracef("BlobsDel: %v %x", treeID, digests)

	// Verify tree exists. We allow blobs to be deleted from both
	// frozen and non frozen trees.
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Get all tree leaves
	leaves, err := t.tlog.leavesAll(treeID)
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
			ed, err := extraDataDecode(v.ExtraData)
			if err != nil {
				return err
			}
			keys = append(keys, ed.Key)
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
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) Blobs(treeID int64, digests [][]byte) (map[string]store.BlobEntry, error) {
	log.Tracef("Blobs: %v %x", treeID, digests)

	if len(digests) == 0 {
		return map[string]store.BlobEntry{}, nil
	}

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get leaves
	leavesAll, err := t.tlog.leavesAll(treeID)
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
		ed, err := extraDataDecode(l.ExtraData)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ed.Key)
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

// BlobsByDataDesc returns all blobs that match the provided data descriptor.
// The blobs will be ordered from oldest to newest.
//
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) BlobsByDataDesc(treeID int64, dataDesc string) ([]store.BlobEntry, error) {
	log.Tracef("BlobsByDataDesc: %v %v", treeID, dataDesc)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get leaves
	leaves, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the key-value store keys for all
	// leaves with a matching key prefix.
	keys := make([]string, 0, len(leaves))
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDesc {
			keys = append(keys, ed.Key)
		}
	}
	if len(keys) == 0 {
		return []store.BlobEntry{}, nil
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

// DigestsByDataDesc returns the digests of all blobs that match the provided
// data descriptor.
//
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) DigestsByDataDesc(treeID int64, dataDesc string) ([][]byte, error) {
	log.Tracef("DigestsByDataDesc: %v %v", treeID, dataDesc)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get leaves
	leaves, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the digests, i.e. the leaf value, of
	// all leaves that match the provided data type.
	digests := make([][]byte, 0, len(leaves))
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDesc {
			digests = append(digests, v.LeafValue)
		}
	}

	return digests, nil
}

// Timestamp returns the timestamp for the data blob that corresponds to the
// provided digest.
//
// This function satisfies the plugins TstoreClient interface.
func (t *Tstore) Timestamp(treeID int64, digest []byte) (*backend.Timestamp, error) {
	log.Tracef("Timestamp: %v %x", treeID, digest)

	// Get tree leaves
	leaves, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Get merkle leaf hash
	m := merkleLeafHash(digest)

	// Get timestamp
	return t.timestamp(treeID, m, leaves)
}
