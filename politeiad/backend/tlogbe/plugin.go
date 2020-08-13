// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

type HookT int

const (
	// Plugin hooks
	HookInvalid             HookT = 0
	HookPreNewRecord        HookT = 1
	HookPostNewRecord       HookT = 2
	HookPreEditRecord       HookT = 3
	HookPostEditRecord      HookT = 4
	HookPreEditMetadata     HookT = 5
	HookPostEditMetadata    HookT = 6
	HookPreSetRecordStatus  HookT = 7
	HookPostSetRecordStatus HookT = 8
)

var (
	// Hooks contains human readable plugin hook descriptions.
	Hooks = map[HookT]string{
		HookPostNewRecord:       "post new record",
		HookPostEditRecord:      "post edit record",
		HookPostEditMetadata:    "post edit metadata",
		HookPostSetRecordStatus: "post set record status",
	}
)

// Plugin provides an API for the tlogbe to use when interacting with plugins.
// All tlogbe plugins must implement the Plugin interface.
type Plugin interface {
	// Perform plugin setup
	Setup() error

	// Execute a plugin command
	Cmd(cmd, payload string) (string, error)

	// Execute a plugin hook
	Hook(h HookT, payload string) error

	// Perform a plugin file system check
	Fsck() error
}

type RecordStateT int

const (
	// Record types
	RecordStateInvalid  RecordStateT = 0
	RecordStateUnvetted RecordStateT = 1
	RecordStateVetted   RecordStateT = 2
)

// RecordClient provides an API for plugins to save, retrieve, and delete
// plugin data for a specific record. Editing data is not allowed.
type RecordClient struct {
	Token  []byte
	State  RecordStateT
	treeID int64
	tlog   *tlog
}

// hashes and keys must share the same ordering.
func (c *RecordClient) Save(keyPrefix string, blobs, hashes [][]byte, encrypt bool) ([][]byte, error) {
	log.Tracef("Save: %x %v %v %x", c.Token, keyPrefix, encrypt, hashes)

	// Ensure tree exists and is not frozen
	if !c.tlog.treeExists(c.treeID) {
		return nil, errRecordNotFound
	}
	_, err := c.tlog.freezeRecord(c.treeID)
	if err != errFreezeRecordNotFound {
		return nil, errTreeIsFrozen
	}

	// Encrypt blobs if specified
	if encrypt {
		for k, v := range blobs {
			e, err := c.tlog.encryptionKey.encrypt(0, v)
			if err != nil {
				return nil, err
			}
			blobs[k] = e
		}
	}

	// Save blobs to store
	keys, err := c.tlog.store.Put(blobs)
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
		leaves = append(leaves, logLeafNew(hashes[k], pk))
	}

	// Append leaves to trillian tree
	queued, _, err := c.tlog.trillian.leavesAppend(c.treeID, leaves)
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

	merkles := make([][]byte, 0, len(blobs))
	for _, v := range queued {
		merkles = append(merkles, v.QueuedLeaf.Leaf.MerkleLeafHash)
	}

	return merkles, nil
}

func (c *RecordClient) Del(merkleHashes [][]byte) error {
	log.Tracef("Del: %x %x", c.Token, merkleHashes)

	// Ensure tree exists. We allow blobs to be deleted from both
	// frozen and non frozen trees.
	if !c.tlog.treeExists(c.treeID) {
		return errRecordNotFound
	}

	// Get all tree leaves
	leaves, err := c.tlog.trillian.leavesAll(c.treeID)
	if err != nil {
		return err
	}

	// Aggregate the key-value store keys for the provided merkle
	// hashes.
	merkles := make(map[string]struct{}, len(leaves))
	for _, v := range merkleHashes {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}
	keys := make([]string, 0, len(merkles))
	for _, v := range leaves {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if ok {
			key, err := extractKeyFromLeaf(v)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
	}

	// Delete file blobs from the store
	err = c.tlog.store.Del(keys)
	if err != nil {
		return fmt.Errorf("store Del: %v", err)
	}

	return nil
}

// If a blob does not exist it will not be included in the returned map. It is
// the responsibility of the caller to check that a blob is returned for each
// of the provided merkle hashes.
func (c *RecordClient) BlobsByMerkleHash(merkleHashes [][]byte) (map[string][]byte, error) {
	log.Tracef("BlobsByMerkleHash: %x %x", c.Token, merkleHashes)

	// Get leaves
	leavesAll, err := c.tlog.trillian.leavesAll(c.treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Aggregate the leaves that correspond to the provided merkle
	// hashes.
	// map[merkleHash]*trillian.LogLeaf
	leaves := make(map[string]*trillian.LogLeaf, len(merkleHashes))
	for _, v := range merkleHashes {
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
	for _, v := range merkleHashes {
		l, ok := leaves[hex.EncodeToString(v)]
		if !ok {
			return nil, fmt.Errorf("leaf not found for merkle hash: %x", v)
		}
		k, err := extractKeyFromLeaf(l)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	// Pull the blobs from the store. If is ok if one or more blobs is
	// not found. It is the responsibility of the caller to decide how
	// this should be handled.
	blobs, err := c.tlog.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}

	// Decrypt any encrypted blobs
	for k, v := range blobs {
		if blobIsEncrypted(v) {
			b, _, err := c.tlog.encryptionKey.decrypt(v)
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
		merkleHash := hex.EncodeToString(merkleHashes[k])
		blob, ok := blobs[v]
		if !ok {
			return nil, fmt.Errorf("blob not found for key %v", v)
		}
		b[merkleHash] = blob
	}

	return b, nil
}

func (c *RecordClient) BlobsByKeyPrefix(keyPrefix string) ([][]byte, error) {
	log.Tracef("BlobsByKeyPrefix: %x %x", c.Token, keyPrefix)

	// Get leaves
	leaves, err := c.tlog.trillian.leavesAll(c.treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Walk leaves and aggregate the key-value store keys for all
	// leaves with a matching key prefix.
	keys := make([]string, 0, len(leaves))
	for _, v := range leaves {
		if bytes.HasPrefix(v.ExtraData, []byte(keyPrefix)) {
			k, err := extractKeyFromLeaf(v)
			if err != nil {
				return nil, err
			}
			keys = append(keys, k)
		}
	}

	// Pull the blobs from the store
	blobs, err := c.tlog.store.Get(keys)
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
			b, _, err := c.tlog.encryptionKey.decrypt(v)
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

// TODO implement RecordClient
func (t *Tlogbe) RecordClient(token []byte) (*RecordClient, error) {
	return nil, nil
}
