// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/google/trillian"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
)

// Client provides an API for plugins to interact with a tstore instance.
// Plugins are allowed to save, delete, and retrieve plugin data to/from the
// tstore instance.
//
// Client satisfies the plugins TstoreClient interface.
type Client struct {
	id     string // Caller ID used for logging
	tstore *Tstore

	// Client write methods use the tx for all read/write operations.
	tx store.Tx

	// Client read methods use the getter for all operations. This
	// allows the caller to decide whether the operations should be
	// part of a store Tx or executed individually use the BlobKV
	// interface directly.
	getter store.Getter
}

// newClient returns a new tstore Client.
func newClient(id string, tstore *Tstore, tx store.Tx, getter store.Getter) *Client {
	return &Client{
		id:     id,
		tstore: tstore,
		tx:     tx,
		getter: getter,
	}
}

// BlobSave saves a BlobEntry to tstore.
//
// If the record is unvetted the BlobEntry will be encrypted prior to being
// written to disk.
//
// The digest of the data, i.e. BlobEntry.Digest, can be thought of as the blob
// ID and can be used to get/del the blob from tstore.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) BlobSave(token []byte, be store.BlobEntry) error {
	log.Tracef("%v BlobSave: %x", c.id, token)

	// Verify that the tlog tree is not frozen.
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
	if err != nil {
		return err
	}
	idx, err := c.tstore.recordIndexLatest(c.tx, leaves)
	if err != nil {
		return err
	}
	if idx.Frozen {
		// The tree is frozen. The record is locked.
		return backend.ErrRecordLocked
	}

	// Only vetted data should be saved cleartext.
	var encrypt bool
	switch idx.State {
	case backend.StateUnvetted:
		encrypt = true
	case backend.StateVetted:
		encrypt = false
	default:
		// Should not happen
		return errors.Errorf("invalid record state %v %v", treeID, idx.State)
	}

	// Save the blob to the kv store.
	b, err := store.Blobify(be)
	if err != nil {
		return err
	}
	key := newStoreKey(encrypt)
	err = c.tx.Put(map[string][]byte{key: b}, encrypt)
	if err != nil {
		return err
	}

	// Parse the data descriptor. The data descriptor is pulled
	// out and saved as part of the leaf extra data so that we
	// know the type of blob that the leaf corresponds to without
	// having to pull the blob from the kv store and look.
	b, err = base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return err
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return err
	}

	// Append a leaf to the tlog tree for the blob. The digest of
	// the blob entry is saved as the leaf value. The kv store key
	// for the blob is saved as part of the leaf extra data.
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	ed := newExtraData(key, dd.Descriptor, idx.State)
	extraData, err := ed.encode()
	if err != nil {
		return err
	}
	leaves = []*trillian.LogLeaf{
		newLogLeaf(digest, extraData),
	}

	// Append log leaf to trillian tree
	queued, _, err := c.tstore.tlog.LeavesAppend(treeID, leaves)
	if err != nil {
		return err
	}
	if len(queued) != 1 {
		return errors.Errorf("wrong queued leaves count: got %v, want 1",
			len(queued))
	}
	code := codes.Code(queued[0].QueuedLeaf.GetStatus().GetCode())
	switch code {
	case codes.OK:
		// This is ok; continue
	case codes.AlreadyExists:
		return backend.ErrDuplicatePayload
	default:
		return errors.Errorf("queued leaf error: %v", code)
	}

	log.Debugf("Saved blob %v", dd.Descriptor)

	return nil
}

// BlobsDel deletes the blobs that correspond to the provided digests. Blobs
// can be deleted from both frozen and non-frozen records.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) BlobsDel(token []byte, digests [][]byte) error {
	log.Tracef("%v BlobsDel: %x %x", c.id, token, digests)

	// Get all tree leaves
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
	if err != nil {
		return err
	}

	// Put merkle leaf hashes into a map so that we can tell if a
	// leaf corresponds to one of the target merkle leaf hashes in
	// O(n) time.
	merkleHashes := make(map[string]struct{}, len(digests))
	for _, v := range digests {
		m := hex.EncodeToString(merkleLeafHash(v))
		merkleHashes[m] = struct{}{}
	}

	// Aggregate the key-value store keys for the provided merkle
	// leaf hashes.
	keys := make([]string, 0, len(digests))
	for _, v := range leaves {
		_, ok := merkleHashes[hex.EncodeToString(v.MerkleLeafHash)]
		if ok {
			ed, err := decodeExtraData(v.ExtraData)
			if err != nil {
				return err
			}
			keys = append(keys, ed.key())
		}
	}

	// Delete file blobs from the store
	err = c.tx.Del(keys)
	if err != nil {
		return err
	}

	return nil
}

// Blobs returns the blobs that correspond to the provided digests. If a blob
// does not exist it will not be included in the returned map. If a record is
// vetted, only vetted blobs will be returned.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) Blobs(token []byte, digests [][]byte) (map[string]store.BlobEntry, error) {
	log.Tracef("%v Blobs: %x %x", c.id, token, digests)

	if len(digests) == 0 {
		return map[string]store.BlobEntry{}, nil
	}

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
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
		ed, err := decodeExtraData(v.ExtraData)
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
			matchedKeys = append(matchedKeys, ed.key())
		}
	}
	if len(matchedKeys) == 0 {
		return map[string]store.BlobEntry{}, nil
	}

	// Pull the blobs from the store
	blobs, err := c.getter.Get(matchedKeys)
	if err != nil {
		return nil, err
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
func (c *Client) BlobsByDataDesc(token []byte, dataDesc []string) ([]store.BlobEntry, error) {
	log.Tracef("%v BlobsByDataDesc: %x %v", c.id, token, dataDesc)

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
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
		ed, err := decodeExtraData(v.ExtraData)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ed.key())
	}

	// Pull the blobs from the store
	blobs, err := c.getter.Get(keys)
	if err != nil {
		return nil, err
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
		return nil, errors.Errorf("blobs not found: %v", missing)
	}

	// Prepare reply. The blob entries should be in the same order as
	// the keys, i.e. ordered from oldest to newest.
	entries := make([]store.BlobEntry, 0, len(keys))
	for _, v := range keys {
		b, ok := blobs[v]
		if !ok {
			return nil, errors.Errorf("blob not found: %v", v)
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
func (c *Client) DigestsByDataDesc(token []byte, dataDesc []string) ([][]byte, error) {
	log.Tracef("%v DigestsByDataDesc: %x %v", c.id, token, dataDesc)

	// Get leaves
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
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
func (c *Client) Timestamp(token []byte, digest []byte) (*backend.Timestamp, error) {
	log.Tracef("%v Timestamp: %x %x", c.id, token, digest)

	// Get tree leaves
	treeID := treeIDFromToken(token)
	leaves, err := c.tstore.leavesAll(treeID)
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
			ed, err := decodeExtraData(v.ExtraData)
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
	return c.tstore.timestamp(treeID, m, leaves)
}

// CacheSave saves the provided key-value pairs to the tstore cache. Cached
// data is not timestamped onto the Decred blockchain. Only data that can be
// recreated by walking the tlog trees should be cached.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) CacheSave(kv map[string][]byte) error {
	log.Tracef("%v CacheSave: %v blobs", c.id, len(kv))

	return c.tx.Put(kv, true)
}

// CacheGet returns blobs from the cache for the provided keys. An entry will
// not exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) CacheGet(keys []string) (map[string][]byte, error) {
	log.Tracef("%v CacheGet: %v", c.id, keys)

	return c.getter.Get(keys)
}

// Record returns a version of a record.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) Record(token []byte, version uint32) (*backend.Record, error) {
	log.Tracef("%v Record: %x %v", c.id, token, version)

	// Read methods are allow to provide shortened tokens.
	// Verify that we have the full length token.
	var err error
	token, err = c.tstore.fullLengthToken(token)
	if err != nil {
		return nil, err
	}

	treeID := treeIDFromToken(token)
	return c.tstore.record(c.getter, treeID, version, []string{}, false)
}

// RecordLatest returns the most recent version of a record.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) RecordLatest(token []byte) (*backend.Record, error) {
	log.Tracef("%v RecordLatest: %x", c.id, token)

	// Read methods are allow to provide shortened tokens.
	// Verify that we have the full length token.
	var err error
	token, err = c.tstore.fullLengthToken(token)
	if err != nil {
		return nil, err
	}

	treeID := treeIDFromToken(token)
	return c.tstore.record(c.getter, treeID, 0, []string{}, false)
}

// RecordPartial returns a partial record. This method gives the caller fine
// grained control over what version and what files are returned. The only
// required field is the token. All other fields are optional.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is not empty
// then the specified files will be the only files that are returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) RecordPartial(token []byte, version uint32, filenames []string, omitAllFiles bool) (*backend.Record, error) {
	log.Tracef("%v RecordPartial: %x %v %v %v",
		c.id, token, version, filenames, omitAllFiles)

	// Read methods are allow to provide shortened tokens.
	// Verify that we have the full length token.
	var err error
	token, err = c.tstore.fullLengthToken(token)
	if err != nil {
		return nil, err
	}

	treeID := treeIDFromToken(token)
	return c.tstore.record(c.getter, treeID, version, filenames, omitAllFiles)
}

// RecordState returns the record state.
//
// This function satisfies the plugins TstoreClient interface.
func (c *Client) RecordState(token []byte) (backend.StateT, error) {
	log.Tracef("%v RecordState: %x", c.id, token)

	return c.tstore.RecordState(token)
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
		ed, err := decodeExtraData(v.ExtraData)
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
