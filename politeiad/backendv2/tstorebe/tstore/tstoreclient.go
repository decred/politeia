// Copyright (c) 2020-2022 The Decred developers
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
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

var (
	_ plugins.TstoreClient = (*tstoreClient)(nil)
)

// tstoreClient satisfies the plugin TstoreClient interface.
type tstoreClient struct {
	pluginID string
	tstore   *Tstore
}

// BlobSave saves a BlobEntry to the tstore instance. The BlobEntry will be
// encrypted prior to being written to disk if the record is unvetted. The
// digest of the data, i.e. BlobEntry.Digest, can be thought of as the blob ID
// and can be used to get/del the blob from tstore.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) BlobSave(token []byte, be store.BlobEntry) error {
	log.Tracef("BlobSave: %x", token)

	// Verify tree is not frozen
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return err
	}
	idx, err := t.tstore.recordIndexLatest(leaves)
	if err != nil {
		return err
	}
	if idx.Frozen {
		// The tree is frozen. The record is locked.
		return backend.ErrRecordLocked
	}

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

	// Only vetted data should be saved plain text
	var encrypt bool
	switch idx.State {
	case backend.StateUnvetted:
		encrypt = true
	case backend.StateVetted:
		// Save plain text
		encrypt = false
	default:
		// Something is wrong
		panic(fmt.Sprintf("invalid record state %v %v", treeID, idx.State))
	}

	// Prepare blob and digest
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	blob, err := store.Blobify(be)
	if err != nil {
		return err
	}
	key := storeKeyNew(encrypt)
	kv := map[string][]byte{key: blob}

	log.Debugf("Saving plugin data blob %v", dd.Descriptor)

	// Save blob to store
	err = t.tstore.store.Put(kv, encrypt)
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}

	// Prepare log leaf
	extraData, err := extraDataEncode(key, dd.Descriptor, idx.State)
	if err != nil {
		return err
	}
	leaves = []*trillian.LogLeaf{
		newLogLeaf(digest, extraData),
	}

	// Append log leaf to trillian tree
	queued, _, err := t.tstore.tlog.LeavesAppend(treeID, leaves)
	if err != nil {
		return fmt.Errorf("LeavesAppend: %v", err)
	}
	if len(queued) != 1 {
		return fmt.Errorf("wrong queued leaves count: got %v, want 1",
			len(queued))
	}
	c := codes.Code(queued[0].QueuedLeaf.GetStatus().GetCode())
	switch c {
	case codes.OK:
		// This is ok; continue
	case codes.AlreadyExists:
		return backend.ErrDuplicatePayload
	default:
		return fmt.Errorf("queued leaf error: %v", c)
	}

	return nil
}

// BlobsDel deletes the blobs that correspond to the provided digests. Blobs
// can be deleted from both frozen and non-frozen records.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) BlobsDel(token []byte, digests [][]byte) error {
	log.Tracef("BlobsDel: %x %x", token, digests)

	// Get all tree leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return err
	}

	// Put merkle leaf hashes into a map so that we can tell if a leaf
	// corresponds to one of the target merkle leaf hashes in O(n)
	// time.
	merkleHashes := make(map[string]struct{}, len(digests))
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
			keys = append(keys, ed.storeKey())
		}
	}

	// Delete file blobs from the store
	err = t.tstore.store.Del(keys)
	if err != nil {
		return fmt.Errorf("store Del: %v", err)
	}

	return nil
}

// Blobs returns the blobs that correspond to the provided digests. If a blob
// does not exist it will not be included in the returned map. If a record
// is vetted, only vetted blobs will be returned.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) Blobs(token []byte, digests [][]byte) (map[string]store.BlobEntry, error) {
	log.Tracef("Blobs: %x %x", token, digests)

	if len(digests) == 0 {
		return map[string]store.BlobEntry{}, nil
	}

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return nil, err
	}

	// Determine if the record is vetted. If the record is vetted, only
	// vetted blobs will be returned.
	isVetted := recordIsVetted(leaves)

	// Put digests into a map
	ds := make(map[string]struct{}, len(digests))
	for _, v := range digests {
		ds[hex.EncodeToString(v)] = struct{}{}
	}

	// Find the log leaves for the provided digests. matchedLeaves and
	// matchedKeys MUST share the same ordering.
	var (
		matchedLeaves = make([]*trillian.LogLeaf, 0, len(digests))
		matchedKeys   = make([]string, 0, len(digests))
	)
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		if isVetted && ed.State == backend.StateUnvetted {
			// We don't return unvetted blobs if the record is vetted
			continue
		}

		// Check if this is one of the target digests
		if _, ok := ds[hex.EncodeToString(v.LeafValue)]; ok {
			// Its a match!
			matchedLeaves = append(matchedLeaves, v)
			matchedKeys = append(matchedKeys, ed.storeKey())
		}
	}
	if len(matchedKeys) == 0 {
		return map[string]store.BlobEntry{}, nil
	}

	// Pull the blobs from the store
	blobs, err := t.tstore.store.Get(matchedKeys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}

	// Prepare reply
	entries := make(map[string]store.BlobEntry, len(matchedKeys))
	for i, v := range matchedKeys {
		b, ok := blobs[v]
		if !ok {
			// Blob wasn't found in the store. Skip it.
			continue
		}
		be, err := store.Deblob(b)
		if err != nil {
			return nil, err
		}

		// Get the corresponding digest
		l := matchedLeaves[i]
		digest := hex.EncodeToString(l.LeafValue)
		entries[digest] = *be
	}

	return entries, nil
}

// BlobsByDataDesc returns all blobs that match the provided data descriptors.
// The blobs will be ordered from oldest to newest. If a record is vetted then
// only vetted blobs will be returned.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) BlobsByDataDesc(token []byte, dataDesc []string) ([]store.BlobEntry, error) {
	log.Tracef("BlobsByDataDesc: %x %v", token, dataDesc)

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return nil, err
	}

	// Find all matching leaves
	matches := leavesForDescriptor(leaves, dataDesc)
	if len(matches) == 0 {
		return []store.BlobEntry{}, nil
	}

	// Aggregate the keys of all the matches
	keys := make([]string, 0, len(matches))
	for _, v := range matches {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ed.storeKey())
	}

	// Pull the blobs from the store
	blobs, err := t.tstore.store.Get(keys)
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
		be, err := store.Deblob(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	return entries, nil
}

// DigestsByDataDesc returns the digests of all blobs that match the provided
// data descriptor. If a record is vetted then only vetted digests will be
// returned.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) DigestsByDataDesc(token []byte, dataDesc []string) ([][]byte, error) {
	log.Tracef("DigestsByDataDesc: %x %v", token, dataDesc)

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return nil, err
	}

	// Find all matching leaves
	matches := leavesForDescriptor(leaves, dataDesc)

	// Aggregate the digests, i.e. the leaf value, for all the matches
	digests := make([][]byte, 0, len(matches))
	for _, v := range matches {
		digests = append(digests, v.LeafValue)
	}

	return digests, nil
}

// Timestamp returns the timestamp for the data blob that corresponds to the
// provided digest. If a record is vetted, only vetted timestamps will be
// returned.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) Timestamp(token []byte, digest []byte) (*backend.Timestamp, error) {
	log.Tracef("Timestamp: %x %x", token, digest)

	// Get tree leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.tstore.leavesAll(treeID)
	if err != nil {
		return nil, err
	}

	// Determine if the record is vetted
	isVetted := recordIsVetted(leaves)

	// If the record is vetted we cannot return an unvetted timestamp.
	// Find the leaf for the digest and verify that its not unvetted.
	if isVetted {
		for _, v := range leaves {
			if !bytes.Equal(v.LeafValue, digest) {
				// Not the target leaf
				continue
			}

			// This is the target leaf. Verify that its vetted.
			ed, err := extraDataDecode(v.ExtraData)
			if err != nil {
				return nil, err
			}
			if ed.State != backend.StateVetted {
				log.Debugf("Caller is requesting an unvetted timestamp " +
					"for a vetted record; not allowed")
				return &backend.Timestamp{
					Proofs: []backend.Proof{},
				}, nil
			}
		}
	}

	// Get merkle leaf hash
	m := merkleLeafHash(digest)

	// Get timestamp
	return t.tstore.timestamp(treeID, m, leaves)
}

// CachePut saves the provided key-value pairs to the key-value store. It
// prefixes the keys with the plugin ID in order to limit the access of the
// plugins only to the data they own.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) CachePut(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("CachePut: %v %v", t.pluginID, encrypt)

	// Prefix keys with pluginID, in order to strict plugins access only to
	// the data they own.
	prefixedBlobs := prefixMapKeys(t.pluginID, blobs)

	return t.tstore.store.Put(prefixedBlobs, encrypt)
}

// CacheDel deletes the provided blobs from the key-value store. This
// operation is performed atomically. It prefixes the keys with the plugin
// ID in order to limit the access of the plugins only to the data they own.
//
// This function satisfies the plugins TstoreClient interface.
func (t *tstoreClient) CacheDel(keys []string) error {
	log.Tracef("CacheDel: %v %v", t.pluginID, keys)

	// Prefix keys with pluginID, in order to strict plugins access only to
	// the data they own.
	pkeys := prefixKeys(t.pluginID, keys)

	return t.tstore.store.Del(pkeys)
}

// CacheGet returns blobs from the key-value store for the provided keys. An
// entry will not exist in the returned map if for any blobs that are not
// found. It is the responsibility of the caller to ensure a blob
// was returned for all provided keys. It prefixes the keys with the plugin
// ID in order to limit the access of the plugins only to the data they own.
func (t *tstoreClient) CacheGet(keys []string) (map[string][]byte, error) {
	log.Tracef("CacheGet: %v %v", t.pluginID, keys)

	// Prefix keys with pluginID, in order to strict plugins access only to
	// the data they own.
	pkeys := prefixKeys(t.pluginID, keys)

	return t.tstore.store.Get(pkeys)
}

// Record is a wrapper of the tstore Record func.
func (t *tstoreClient) Record(token []byte, version uint32) (*backend.Record, error) {
	return t.tstore.Record(token, version)
}

// RecordLatest is a wrapper of the tstore RecordLatest func.
func (t *tstoreClient) RecordLatest(token []byte) (*backend.Record, error) {
	return t.tstore.RecordLatest(token)
}

// RecordPartial is a wrapper of the tstore RecordPartial func.
func (t *tstoreClient) RecordPartial(token []byte, version uint32, filenames []string, omitAllFiles bool) (*backend.Record, error) {
	return t.tstore.RecordPartial(token, version, filenames, omitAllFiles)
}

// RecordState is a wraper of the tstore RecordState func.
func (t *tstoreClient) RecordState(token []byte) (backend.StateT, error) {
	return t.tstore.RecordState(token)
}

// leavesForDescriptor returns all leaves that have and extra data descriptor
// that matches the provided descriptor. If a record is vetted, only vetted
// leaves will be returned.
func leavesForDescriptor(leaves []*trillian.LogLeaf, descriptors []string) []*trillian.LogLeaf {
	// Put descriptors into a map for 0(n) lookups
	desc := make(map[string]struct{}, len(descriptors))
	for _, v := range descriptors {
		desc[v] = struct{}{}
	}

	// Determine if the record is vetted. If the record is vetted then
	// only vetted leaves will be returned.
	isVetted := recordIsVetted(leaves)

	// Walk leaves and aggregate all leaves that match the provided
	// data descriptor.
	matches := make([]*trillian.LogLeaf, 0, len(leaves))
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			panic(err)
		}
		if _, ok := desc[ed.Desc]; !ok {
			// Not one of the data descriptor we're looking for
			continue
		}
		if isVetted && ed.State != backend.StateVetted {
			// Unvetted leaf on a vetted record. Don't use it.
			continue
		}

		// We have a match!
		matches = append(matches, v)
	}

	return matches
}

// prefixMapKeys accepts a map of []byte indexed by string keys, and it
// prefixes all the map keys with the given string prefix.
func prefixMapKeys(prefix string, m map[string][]byte) map[string][]byte {
	pm := make(map[string][]byte, len(m))

	for k, v := range m {
		pm[prefix+"-"+k] = v
	}

	return pm
}

// prefixKeys accepts a list of string keys, and it returns the keys prefixed
// with the given prefix.
func prefixKeys(prefix string, keys []string) []string {
	pkeys := make([]string, 0, len(keys))
	for _, key := range keys {
		pkeys = append(pkeys, prefix+"-"+key)
	}

	return pkeys
}
