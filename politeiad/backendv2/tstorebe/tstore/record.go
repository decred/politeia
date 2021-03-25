// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

const (
	// Blob entry data descriptors
	dataDescriptorRecordMetadata = "pd-recordmd-v1"
	dataDescriptorMetadataStream = "pd-mdstream-v1"
	dataDescriptorFile           = "pd-file-v1"
	dataDescriptorRecordIndex    = "pd-rindex-v1"
	dataDescriptorAnchor         = "pd-anchor-v1"
)

// recordBlobsSave saves the provided blobs to the kv store, appends a leaf
// to the trillian tree for each blob, and returns the record index for the
// blobs.
func (t *Tstore) recordBlobsSave(treeID int64, leavesAll []*trillian.LogLeaf, recordMD backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) (*recordIndex, error) {
	log.Tracef("recordBlobsSave: %v", treeID)

	// Verify there are no duplicate metadata streams
	md := make(map[string]map[uint32]struct{}, len(metadata))
	for _, v := range metadata {
		if v.PluginID == "" || v.StreamID == 0 {
			return nil, fmt.Errorf("invalid metadata stream: '%v' %v",
				v.PluginID, v.StreamID)
		}
		pmd, ok := md[v.PluginID]
		if !ok {
			pmd = make(map[uint32]struct{}, len(metadata))
		}
		_, ok = pmd[v.StreamID]
		if ok {
			return nil, fmt.Errorf("duplicate metadata stream: %v %v",
				v.PluginID, v.StreamID)
		}
		pmd[v.StreamID] = struct{}{}
		md[v.PluginID] = pmd
	}

	// Verify there are no duplicate files
	fn := make(map[string]struct{}, len(files))
	for _, v := range files {
		if v.Name == "" {
			return nil, fmt.Errorf("empty filename")
		}
		_, ok := fn[v.Name]
		if ok {
			return nil, fmt.Errorf("duplicate filename found: %v", v.Name)
		}
		fn[v.Name] = struct{}{}
	}

	// Prepare the blob entries. The record index can also be created
	// during this step.
	var (
		// [pluginID][streamID]BlobEntry
		beMetadata = make(map[string]map[uint32]store.BlobEntry, len(metadata))

		// [filename]BlobEntry
		beFiles = make(map[string]store.BlobEntry, len(files))

		idx = recordIndex{
			State:     recordMD.State,
			Version:   recordMD.Version,
			Iteration: recordMD.Iteration,
			Metadata:  make(map[string]map[uint32][]byte, len(metadata)),
			Files:     make(map[string][]byte, len(files)),
		}

		// digests is used to aggregate the digests from all record
		// content. This is used later on to see if any of the content
		// already exists in the tstore.
		digests = make(map[string]struct{}, 256)
	)

	// Setup record metadata
	beRecordMD, err := convertBlobEntryFromRecordMetadata(recordMD)
	if err != nil {
		return nil, err
	}
	m, err := merkleLeafHashForBlobEntry(*beRecordMD)
	if err != nil {
		return nil, err
	}
	idx.RecordMetadata = m
	digests[beRecordMD.Digest] = struct{}{}

	// Setup metdata streams
	for _, v := range metadata {
		// Blob entry
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		streams, ok := beMetadata[v.PluginID]
		if !ok {
			streams = make(map[uint32]store.BlobEntry, len(metadata))
		}
		streams[v.StreamID] = *be
		beMetadata[v.PluginID] = streams

		// Record index
		m, err := merkleLeafHashForBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		streamsIdx, ok := idx.Metadata[v.PluginID]
		if !ok {
			streamsIdx = make(map[uint32][]byte, len(metadata))
		}
		streamsIdx[v.StreamID] = m
		idx.Metadata[v.PluginID] = streamsIdx

		// Aggregate digest
		digests[be.Digest] = struct{}{}
	}

	// Setup files
	for _, v := range files {
		// Blob entry
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		beFiles[v.Name] = *be

		// Record Index
		m, err := merkleLeafHashForBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		idx.Files[v.Name] = m

		// Aggregate digest
		digests[be.Digest] = struct{}{}
	}

	// Check if any of the content already exists. Different record
	// versions that reference the same data is fine, but this data
	// should not be saved to the store again. We can find duplicates
	// by comparing the blob entry digest to the log leaf value. They
	// will be the same if the record content is the same.
	dups := make(map[string]struct{}, len(digests))
	for _, v := range leavesAll {
		d := hex.EncodeToString(v.LeafValue)
		_, ok := digests[d]
		if ok {
			// A piece of the new record content already exsits in the
			// tstore. Save the digest as a duplcate.
			dups[d] = struct{}{}
		}
	}

	// Prepare blobs for the kv store
	var (
		blobs  = make(map[string][]byte, len(digests))
		leaves = make([]*trillian.LogLeaf, 0, len(blobs))

		// dupBlobs contains the blob entries for record content that
		// already exists. We may need these blob entries later on if
		// the duplicate content is encrypted and it needs to be saved
		// plain text.
		dupBlobs = make(map[string]store.BlobEntry, len(digests))
	)

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

	// Prepare record metadata blobs and leaves
	_, ok := dups[beRecordMD.Digest]
	if !ok {
		// Not a duplicate. Prepare kv store blob.
		b, err := store.Blobify(*beRecordMD)
		if err != nil {
			return nil, err
		}
		k := storeKeyNew(encrypt)
		blobs[k] = b

		// Prepare tlog leaf
		extraData, err := extraDataEncode(k,
			dataDescriptorRecordMetadata, idx.State)
		if err != nil {
			return nil, err
		}
		digest, err := hex.DecodeString(beRecordMD.Digest)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, newLogLeaf(digest, extraData))
	} else {
		// This is a duplicate. Stash is for now. We may need to save
		// it as plain text later.
		dupBlobs[beRecordMD.Digest] = *beRecordMD
	}

	// Prepare metadata stream blobs and leaves
	for _, v := range beMetadata {
		for _, be := range v {
			_, ok := dups[be.Digest]
			if ok {
				// This is a duplicate. Stash is for now. We may need to save
				// it as plain text later.
				dupBlobs[be.Digest] = be
				continue
			}

			// Not a duplicate. Prepare kv store blob.
			b, err := store.Blobify(be)
			if err != nil {
				return nil, err
			}
			k := storeKeyNew(encrypt)
			blobs[k] = b

			// Prepare tlog leaf
			extraData, err := extraDataEncode(k,
				dataDescriptorMetadataStream, idx.State)
			if err != nil {
				return nil, err
			}
			digest, err := hex.DecodeString(be.Digest)
			if err != nil {
				return nil, err
			}

			leaves = append(leaves, newLogLeaf(digest, extraData))
		}
	}

	// Prepare file blobs and leaves
	for _, be := range beFiles {
		_, ok := dups[be.Digest]
		if ok {
			// This is a duplicate. Stash is for now. We may need to save
			// it as plain text later.
			dupBlobs[be.Digest] = be
			continue
		}

		// Not a duplicate. Prepare kv store blob.
		b, err := store.Blobify(be)
		if err != nil {
			return nil, err
		}
		k := storeKeyNew(encrypt)
		blobs[k] = b

		// Prepare tlog leaf
		extraData, err := extraDataEncode(k, dataDescriptorFile, idx.State)
		if err != nil {
			return nil, err
		}
		digest, err := hex.DecodeString(be.Digest)
		if err != nil {
			return nil, err
		}

		leaves = append(leaves, newLogLeaf(digest, extraData))
	}

	// Verify at least one new blob is being saved to the kv store
	if len(blobs) == 0 {
		return nil, backend.ErrNoRecordChanges
	}

	log.Debugf("Saving %v record content blobs", len(blobs))

	// Save blobs to the kv store
	err = t.store.Put(blobs, encrypt)
	if err != nil {
		return nil, fmt.Errorf("store Put: %v", err)
	}

	// Append leaves onto the trillian tree
	queued, _, err := t.tlog.LeavesAppend(treeID, leaves)
	if err != nil {
		return nil, fmt.Errorf("LeavesAppend: %v", err)
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

	// When a record is made public the record content needs to be
	// resaved to the key-value store as unencrypted.
	var (
		isPublic = recordMD.Status == backend.StatusPublic

		// Iteration and version are reset back to 1 when a record is
		// made public.
		iterIsReset = recordMD.Iteration == 1
	)
	if !isPublic || !iterIsReset {
		// Record is not being made public. Nothing else to do.
		return &idx, nil
	}

	// Resave all of the duplicate blobs as plain text. A duplicate
	// blob means the record content existed prior to the status
	// change.
	blobs = make(map[string][]byte, len(dupBlobs))
	for _, v := range leavesAll {
		d := hex.EncodeToString(v.LeafValue)
		_, ok := dups[d]
		if !ok {
			// Not a duplicate
			continue
		}

		// This is a duplicate. If its unvetted it will need to be
		// resaved as plain text.
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.State == backend.StateVetted {
			// Not unvetted. No need to resave it.
			continue
		}

		// Prepare plain text blob
		be, ok := dupBlobs[d]
		if !ok {
			// Should not happen
			return nil, fmt.Errorf("blob entry not found %v", d)
		}
		b, err := store.Blobify(be)
		if err != nil {
			return nil, err
		}
		blobs[ed.storeKeyNoPrefix()] = b
	}
	if len(blobs) == 0 {
		// This should not happen
		return nil, fmt.Errorf("no blobs found to resave as plain text")
	}

	log.Debugf("Resaving %v encrypted blobs as plain text", len(blobs))

	err = t.store.Put(blobs, false)
	if err != nil {
		return nil, fmt.Errorf("store Put: %v", err)
	}

	return &idx, nil
}

func (t *Tstore) recordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) (*recordIndex, error) {
	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}

	// Get the existing record index
	currIdx, err := t.recordIndexLatest(leavesAll)
	if errors.Is(err, backend.ErrRecordNotFound) {
		// No record versions exist yet. This is ok.
		currIdx = &recordIndex{
			Metadata: make(map[string]map[uint32][]byte),
			Files:    make(map[string][]byte),
		}
	} else if err != nil {
		return nil, fmt.Errorf("recordIndexLatest: %v", err)
	}

	// Verify tree is not frozen
	if currIdx.Frozen {
		return nil, backend.ErrRecordLocked
	}

	// Save the record
	idx, err := t.recordBlobsSave(treeID, leavesAll, rm, metadata, files)
	if err != nil {
		if err == backend.ErrNoRecordChanges {
			return nil, err
		}
		return nil, fmt.Errorf("recordBlobsSave: %v", err)
	}

	return idx, nil
}

// RecordSave saves the provided record to tstore. Once the record contents
// have been successfully saved to tstore, a recordIndex is created for this
// version of the record and saved to tstore as well. The record update is not
// considered to be valid until the record index has been successfully saved.
// If the record content makes it in but the record index does not, the record
// content blobs are orphaned and ignored.
func (t *Tstore) RecordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	log.Tracef("RecordSave: %v", treeID)

	// Save the record
	idx, err := t.recordSave(treeID, rm, metadata, files)
	if err != nil {
		return err
	}

	// Save the record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

// RecordDel walks the provided tree and deletes all blobs in the store that
// correspond to record files. This is done for all versions and all iterations
// of the record. Record metadata and metadata stream blobs are not deleted.
func (t *Tstore) RecordDel(treeID int64) error {
	log.Tracef("RecordDel: %v", treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Get all tree leaves
	leavesAll, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		return err
	}

	// Ensure tree is frozen. Deleting files from the store is only
	// allowed on frozen trees.
	currIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return err
	}
	if !currIdx.Frozen {
		return fmt.Errorf("tree is not frozen")
	}

	// Retrieve all record indexes
	indexes, err := t.recordIndexes(leavesAll)
	if err != nil {
		return err
	}

	// Aggregate the keys for all file blobs of all versions. The
	// record index points to the log leaf merkle leaf hash. The log
	// leaf contains the kv store key.
	merkles := make(map[string]struct{}, len(leavesAll))
	for _, v := range indexes {
		for _, merkle := range v.Files {
			merkles[hex.EncodeToString(merkle)] = struct{}{}
		}
	}
	keys := make([]string, 0, len(merkles))
	for _, v := range leavesAll {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if ok {
			ed, err := extraDataDecode(v.ExtraData)
			if err != nil {
				return err
			}
			keys = append(keys, ed.storeKey())
		}
	}

	// Delete file blobs from the store
	err = t.store.Del(keys)
	if err != nil {
		return fmt.Errorf("store Del: %v", err)
	}

	return nil
}

// RecordFreeze updates the status of a record then freezes the trillian tree
// to prevent any additional updates.
//
// A tree is considered to be frozen once the record index has been saved with
// its Frozen field set to true. The only thing that can be appended onto a
// frozen tree is one additional anchor record. Once a frozen tree has been
// anchored, the tstore fsck function will update the status of the tree to
// frozen in trillian, at which point trillian will prevent any changes to the
// tree.
func (t *Tstore) RecordFreeze(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	log.Tracef("RecordFreeze: %v", treeID)

	// Save updated record
	idx, err := t.recordSave(treeID, rm, metadata, files)
	if err != nil {
		return err
	}

	// Mark the record as frozen
	idx.Frozen = true

	// Save the record index
	return t.recordIndexSave(treeID, *idx)
}

// record returns the specified record.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is not empty
// then the specified files will be the only files returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
func (t *Tstore) record(treeID int64, version uint32, filenames []string, omitAllFiles bool) (*backend.Record, error) {
	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get tree leaves
	leaves, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}

	// Use the record index to pull the record content from the store.
	// The keys for the record content first need to be extracted from
	// their log leaf.
	idx, err := t.recordIndex(leaves, version)
	if err != nil {
		return nil, err
	}

	// Compile merkle root hashes of record content
	merkles := make(map[string]struct{}, 64)
	merkles[hex.EncodeToString(idx.RecordMetadata)] = struct{}{}
	for _, streams := range idx.Metadata {
		for _, v := range streams {
			merkles[hex.EncodeToString(v)] = struct{}{}
		}
	}
	switch {
	case omitAllFiles:
		// Don't include any files
	case len(filenames) > 0:
		// Only included the specified files
		filesToInclude := make(map[string]struct{}, len(filenames))
		for _, v := range filenames {
			filesToInclude[v] = struct{}{}
		}
		for fn, v := range idx.Files {
			if _, ok := filesToInclude[fn]; ok {
				merkles[hex.EncodeToString(v)] = struct{}{}
			}
		}
	default:
		// Include all files
		for _, v := range idx.Files {
			merkles[hex.EncodeToString(v)] = struct{}{}
		}
	}

	// Walk the tree and extract the record content keys
	keys := make([]string, 0, len(idx.Metadata)+len(idx.Files)+1)
	for _, v := range leaves {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if !ok {
			// Not part of the record content
			continue
		}

		// Leaf is part of record content. Save the kv store key.
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}

		var key string
		switch idx.State {
		case backend.StateVetted:
			// If the record is vetted the content may exist in the store
			// as both an encrypted blob and a plain text blob. Always pull
			// the plaintext blob.
			key = ed.storeKeyNoPrefix()
		default:
			// Pull the encrypted blob
			key = ed.storeKey()
		}
		keys = append(keys, key)
	}

	// Get record content from store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(keys) != len(blobs) {
		// One or more blobs were not found. This is allowed since the
		// blobs for a censored record will not exist, but the record
		// metadata and metadata streams should still be returned.
		log.Tracef("Blobs not found %v: want %v, got %v",
			treeID, len(keys), len(blobs))
	}

	// Decode blobs
	entries := make([]store.BlobEntry, 0, len(keys))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Decode blob entries
	var (
		recordMD *backend.RecordMetadata
		metadata = make([]backend.MetadataStream, 0, len(idx.Metadata))
		files    = make([]backend.File, 0, len(idx.Files))
	)
	for _, v := range entries {
		// Decode the data hint
		b, err := base64.StdEncoding.DecodeString(v.DataHint)
		if err != nil {
			return nil, fmt.Errorf("decode DataHint: %v", err)
		}
		var dd store.DataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return nil, fmt.Errorf("unmarshal DataHint: %v", err)
		}
		if dd.Type != store.DataTypeStructure {
			return nil, fmt.Errorf("invalid data type; got %v, want %v",
				dd.Type, store.DataTypeStructure)
		}

		// Decode the data
		b, err = base64.StdEncoding.DecodeString(v.Data)
		if err != nil {
			return nil, fmt.Errorf("decode Data: %v", err)
		}
		digest, err := hex.DecodeString(v.Digest)
		if err != nil {
			return nil, fmt.Errorf("decode Hash: %v", err)
		}
		if !bytes.Equal(util.Digest(b), digest) {
			return nil, fmt.Errorf("data is not coherent; got %x, want %x",
				util.Digest(b), digest)
		}
		switch dd.Descriptor {
		case dataDescriptorRecordMetadata:
			var rm backend.RecordMetadata
			err = json.Unmarshal(b, &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal RecordMetadata: %v", err)
			}
			recordMD = &rm
		case dataDescriptorMetadataStream:
			var ms backend.MetadataStream
			err = json.Unmarshal(b, &ms)
			if err != nil {
				return nil, fmt.Errorf("unmarshal MetadataStream: %v", err)
			}
			metadata = append(metadata, ms)
		case dataDescriptorFile:
			var f backend.File
			err = json.Unmarshal(b, &f)
			if err != nil {
				return nil, fmt.Errorf("unmarshal File: %v", err)
			}
			files = append(files, f)
		default:
			return nil, fmt.Errorf("invalid descriptor %v", dd.Descriptor)
		}
	}

	return &backend.Record{
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

// Record returns the specified version of the record.
func (t *Tstore) Record(treeID int64, version uint32) (*backend.Record, error) {
	log.Tracef("Record: %v %v", treeID, version)

	return t.record(treeID, version, []string{}, false)
}

// RecordLatest returns the latest version of a record.
func (t *Tstore) RecordLatest(treeID int64) (*backend.Record, error) {
	log.Tracef("RecordLatest: %v", treeID)

	return t.record(treeID, 0, []string{}, false)
}

// RecordPartial returns a partial record. This method gives the caller fine
// grained control over what version and what files are returned. The only
// required field is the token. All other fields are optional.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is not empty
// then the specified files will be the only files returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
func (t *Tstore) RecordPartial(treeID int64, version uint32, filenames []string, omitAllFiles bool) (*backend.Record, error) {
	log.Tracef("RecordPartial: %v %v %v %v",
		treeID, version, omitAllFiles, filenames)

	return t.record(treeID, version, filenames, omitAllFiles)
}

// RecordState returns the state of a record. This call does not require
// retrieving any blobs from the kv store. The record state can be derived from
// only the tlog leaves.
func (t *Tstore) RecordState(treeID int64) (backend.StateT, error) {
	log.Tracef("RecordState: %v", treeID)

	leaves, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		return 0, err
	}

	if recordIsVetted(leaves) {
		return backend.StateVetted, nil
	}

	return backend.StateUnvetted, nil
}

// RecordTimestamps returns the timestamps for the contents of a record.
// Timestamps for the record metadata, metadata streams, and files are all
// returned.
func (t *Tstore) RecordTimestamps(treeID int64, version uint32, token []byte) (*backend.RecordTimestamps, error) {
	log.Tracef("RecordTimestamps: %v %v", treeID, version)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get record index
	leaves, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}
	idx, err := t.recordIndex(leaves, version)
	if err != nil {
		return nil, err
	}

	// Get record metadata timestamp
	rm, err := t.timestamp(treeID, idx.RecordMetadata, leaves)
	if err != nil {
		return nil, fmt.Errorf("record metadata timestamp: %v", err)
	}

	// Get metadata timestamps
	metadata := make(map[string]map[uint32]backend.Timestamp, len(idx.Metadata))
	for pluginID, streams := range idx.Metadata {
		for streamID, merkle := range streams {
			ts, err := t.timestamp(treeID, merkle, leaves)
			if err != nil {
				return nil, fmt.Errorf("metadata %v %v timestamp: %v",
					pluginID, streamID, err)
			}
			sts, ok := metadata[pluginID]
			if !ok {
				sts = make(map[uint32]backend.Timestamp, 64)
			}
			sts[streamID] = *ts
			metadata[pluginID] = sts
		}
	}

	// Get file timestamps
	files := make(map[string]backend.Timestamp, len(idx.Files))
	for k, v := range idx.Files {
		ts, err := t.timestamp(treeID, v, leaves)
		if err != nil {
			return nil, fmt.Errorf("file %v timestamp: %v", k, err)
		}
		files[k] = *ts
	}

	return &backend.RecordTimestamps{
		RecordMetadata: *rm,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

// recordIsVetted returns whether the provided leaves contain any vetted record
// indexes. The presence of a vetted record index means the record is vetted.
// The state of a record index is saved to the leaf extra data, which is how we
// determine if a record index is vetted.
func recordIsVetted(leaves []*trillian.LogLeaf) bool {
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			panic(err)
		}
		if ed.Desc == dataDescriptorRecordIndex &&
			ed.State == backend.StateVetted {
			// Vetted record index found
			return true
		}
	}
	return false
}

// merkleLeafHashForBlobEntry returns the merkle leaf hash for a blob entry.
// The merkle leaf hash can be used to retrieve a leaf from its tlog tree.
func merkleLeafHashForBlobEntry(be store.BlobEntry) ([]byte, error) {
	leafValue, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	return merkleLeafHash(leafValue), nil
}

func convertBlobEntryFromFile(f backend.File) (*store.BlobEntry, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorFile,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromMetadataStream(ms backend.MetadataStream) (*store.BlobEntry, error) {
	data, err := json.Marshal(ms)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorMetadataStream,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromRecordMetadata(rm backend.RecordMetadata) (*store.BlobEntry, error) {
	data, err := json.Marshal(rm)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorRecordMetadata,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}
