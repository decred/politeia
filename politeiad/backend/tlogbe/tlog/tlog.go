// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/robfig/cron"
	"google.golang.org/grpc/codes"
)

const (
	defaultTrillianKeyFilename = "trillian.key"
	defaultStoreDirname        = "store"

	// Blob entry data descriptors
	dataDescriptorFile           = "file_v1"
	dataDescriptorRecordMetadata = "recordmd_v1"
	dataDescriptorMetadataStream = "mdstream_v1"
	dataDescriptorRecordIndex    = "rindex_v1"
	dataDescriptorAnchor         = "anchor_v1"

	// The keys for kv store blobs are saved by stuffing them into the
	// ExtraData field of their corresponding trillian log leaf. The
	// keys are prefixed with one of the follwing identifiers before
	// being added to the log leaf so that we can correlate the leaf
	// to the type of data it represents without having to pull the
	// data out of the store, which can become an issue in situations
	// such as searching for a record index that has been buried by
	// thousands of leaves from plugin data.
	// TODO key prefix app-dataID:
	// TODO the leaf ExtraData field should be hinted. Similar to what
	// we do for blobs.
	dataTypeSeperator     = ":"
	dataTypeRecordIndex   = "rindex"
	dataTypeRecordContent = "rcontent"
	dataTypeAnchorRecord  = "anchor"
)

var (
	_ plugins.TlogClient = (*Tlog)(nil)
)

// TODO change tlog name to tstore.
// We do not unwind.
type Tlog struct {
	sync.Mutex
	id              string
	dataDir         string
	activeNetParams *chaincfg.Params
	trillian        trillianClient
	store           store.Blob
	dcrtime         *dcrtimeClient
	cron            *cron.Cron
	plugins         map[string]plugin // [pluginID]plugin

	// encryptionKey is used to encrypt record blobs before saving them
	// to the key-value store. This is an optional param. Record blobs
	// will not be encrypted if this is left as nil.
	encryptionKey *encryptionKey

	// droppingAnchor indicates whether tlog is in the process of
	// dropping an anchor, i.e. timestamping unanchored trillian trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool
}

// blobIsEncrypted returns whether the provided blob has been prefixed with an
// sbox header, indicating that it is an encrypted blob.
func blobIsEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}

func leafExtraData(dataType, storeKey string) []byte {
	return []byte(dataType + ":" + storeKey)
}

func leafDataType(l *trillian.LogLeaf) string {
	s := bytes.SplitAfter(l.ExtraData, []byte(":"))
	if len(s) != 2 {
		e := fmt.Sprintf("invalid key '%s' for leaf %x",
			l.ExtraData, l.MerkleLeafHash)
		panic(e)
	}
	return string(s[0])
}

func extractKeyFromLeaf(l *trillian.LogLeaf) string {
	s := bytes.SplitAfter(l.ExtraData, []byte(":"))
	if len(s) != 2 {
		e := fmt.Sprintf("invalid key '%s' for leaf %x",
			l.ExtraData, l.MerkleLeafHash)
		panic(e)
	}
	return string(s[1])
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

func convertBlobEntryFromRecordIndex(ri recordIndex) (*store.BlobEntry, error) {
	data, err := json.Marshal(ri)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorRecordIndex,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromAnchor(a anchor) (*store.BlobEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAnchor,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertRecordIndexFromBlobEntry(be store.BlobEntry) (*recordIndex, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorRecordIndex {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorRecordIndex)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var ri recordIndex
	err = json.Unmarshal(b, &ri)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordIndex: %v", err)
	}

	return &ri, nil
}

func convertAnchorFromBlobEntry(be store.BlobEntry) (*anchor, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorAnchor {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorAnchor)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var a anchor
	err = json.Unmarshal(b, &a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor: %v", err)
	}

	return &a, nil
}

func (t *Tlog) blobify(be store.BlobEntry) ([]byte, error) {
	b, err := store.Blobify(be)
	if err != nil {
		return nil, err
	}
	if t.encryptionKey != nil {
		b, err = t.encryptionKey.encrypt(0, b)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (t *Tlog) deblob(b []byte) (*store.BlobEntry, error) {
	var err error
	if t.encryptionKey != nil {
		if !blobIsEncrypted(b) {
			return nil, fmt.Errorf("attempted to decrypt an unecrypted blob")
		}
		b, _, err = t.encryptionKey.decrypt(b)
		if err != nil {
			return nil, err
		}
	}
	be, err := store.Deblob(b)
	if err != nil {
		return nil, err
	}
	return be, nil
}

func (t *Tlog) TreeNew() (int64, error) {
	log.Tracef("%v treeNew", t.id)

	tree, _, err := t.trillian.treeNew()
	if err != nil {
		return 0, err
	}

	return tree.TreeId, nil
}

func (t *Tlog) TreeExists(treeID int64) bool {
	log.Tracef("%v TreeExists: %v", t.id, treeID)

	_, err := t.trillian.tree(treeID)
	return err == nil
}

// TreeFreeze updates the status of a record and freezes the trillian tree as a
// result of a record status change. The tree pointer is the tree ID of the new
// location of the record. This is provided on certain status changes such as
// when a unvetted record is made public and the unvetted record is moved to a
// vetted tree. A value of 0 indicates that no tree pointer exists.
//
// Once the record index has been saved with its frozen field set, the tree
// is considered to be frozen. The only thing that can be appended onto a
// frozen tree is one additional anchor record. Once a frozen tree has been
// anchored, the tlog fsck function will update the status of the tree to
// frozen in trillian, at which point trillian will not allow any additional
// leaves to be appended onto the tree.
func (t *Tlog) TreeFreeze(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, treePointer int64) error {
	log.Tracef("%v TreeFreeze: %v", t.id, treeID)

	// Save metadata
	idx, err := t.metadataSave(treeID, rm, metadata)
	if err != nil {
		return err
	}

	// Update the record index
	idx.Frozen = true
	idx.TreePointer = treePointer

	// Blobify the record index
	be, err := convertBlobEntryFromRecordIndex(*idx)
	if err != nil {
		return err
	}
	idxDigest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	b, err := t.blobify(*be)
	if err != nil {
		return err
	}

	// Save record index blob to the kv store
	keys, err := t.store.Put([][]byte{b})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1", len(keys))
	}

	// Append record index leaf to the trillian tree
	extraData := leafExtraData(dataTypeRecordIndex, keys[0])
	leaves := []*trillian.LogLeaf{
		newLogLeaf(idxDigest, extraData),
	}
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if err != nil {
		return fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queued leaves: got %v, want 1",
			len(queued))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("append leaves failed: %v", failed)
	}

	return nil
}

// TreePointer returns the tree pointer for the provided tree if one exists.
// The returned bool will indicate if a tree pointer was found.
func (t *Tlog) TreePointer(treeID int64) (int64, bool) {
	log.Tracef("%v treePointer: %v", t.id, treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return 0, false
	}

	// Verify record index exists
	var idx *recordIndex
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		err = fmt.Errorf("leavesAll: %v", err)
		goto printErr
	}
	idx, err = t.recordIndexLatest(leavesAll)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			// This is an empty tree. This can happen sometimes if a error
			// occurred during record creation. Return gracefully.
			return 0, false
		}
		err = fmt.Errorf("recordIndexLatest: %v", err)
		goto printErr
	}

	// Check if a tree pointer exists
	if !treePointerExists(*idx) {
		// Tree pointer not found
		return 0, false
	}

	// Tree pointer found!
	return idx.TreePointer, true

printErr:
	log.Errorf("%v treePointer: %v", t.id, err)
	return 0, false
}

// TreesAll returns the IDs of all trees in the tlog instance.
func (t *Tlog) TreesAll() ([]int64, error) {
	trees, err := t.trillian.treesAll()
	if err != nil {
		return nil, err
	}
	treeIDs := make([]int64, 0, len(trees))
	for _, v := range trees {
		treeIDs = append(treeIDs, v.TreeId)
	}
	return treeIDs, nil
}

func (t *Tlog) treeIsFrozen(leaves []*trillian.LogLeaf) bool {
	r, err := t.recordIndexLatest(leaves)
	if err != nil {
		panic(err)
	}
	return r.Frozen
}

type recordHashes struct {
	recordMetadata string            // Record metadata hash
	metadata       map[string]uint64 // [hash]metadataID
	files          map[string]string // [hash]filename
}

type recordBlobsPrepareReply struct {
	// recordIndex is the index for the record content. It is created
	// during the blobs prepare step so that it can be populated with
	// the merkle leaf hashes of duplicate data, i.e. data that remains
	// unchanged between two versions of a record. It will be fully
	// populated once the unique blobs haves been saved to the kv store
	// and appended onto the trillian tree.
	recordIndex recordIndex

	// recordHashes contains a mapping of the record content hashes to
	// the record content type. This is used to populate the record
	// index once the leaves have been appended onto the trillian tree.
	recordHashes recordHashes

	// blobs contains the blobified record content that needs to be
	// saved to the kv store. Hashes contains the hashes of the record
	// content prior to being blobified. These hashes are saved to
	// trilian log leaves. The hashes are SHA256 hashes of the JSON
	// encoded data.
	//
	// blobs and hashes share the same ordering.
	blobs  [][]byte
	hashes [][]byte
}

// recordBlobsPrepare prepares the provided record content to be saved to
// the blob kv store and appended onto a trillian tree.
//
// TODO test this function
func (t *Tlog) recordBlobsPrepare(leavesAll []*trillian.LogLeaf, recordMD backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) (*recordBlobsPrepareReply, error) {
	// Verify there are no duplicate or empty mdstream IDs
	mdstreamIDs := make(map[uint64]struct{}, len(metadata))
	for _, v := range metadata {
		if v.ID == 0 {
			return nil, fmt.Errorf("invalid metadata stream ID 0")
		}
		_, ok := mdstreamIDs[v.ID]
		if ok {
			return nil, fmt.Errorf("duplicate metadata stream ID: %v", v.ID)
		}
		mdstreamIDs[v.ID] = struct{}{}
	}

	// Verify there are no duplicate or empty filenames
	filenames := make(map[string]struct{}, len(files))
	for _, v := range files {
		if v.Name == "" {
			return nil, fmt.Errorf("empty filename")
		}
		_, ok := filenames[v.Name]
		if ok {
			return nil, fmt.Errorf("duplicate filename found: %v", v.Name)
		}
		filenames[v.Name] = struct{}{}
	}

	// Check if any of the content already exists. Different record
	// versions that reference the same data is fine, but this data
	// should not be saved to the store again. We can find duplicates
	// by walking the trillian tree and comparing the hash of the
	// provided record content to the log leaf data, which will be the
	// same for duplicates.

	// Compute record content hashes
	rhashes := recordHashes{
		metadata: make(map[string]uint64, len(metadata)), // [hash]metadataID
		files:    make(map[string]string, len(files)),    // [hash]filename
	}
	b, err := json.Marshal(recordMD)
	if err != nil {
		return nil, err
	}
	rhashes.recordMetadata = hex.EncodeToString(util.Digest(b))
	for _, v := range metadata {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.metadata[h] = v.ID
	}
	for _, v := range files {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.files[h] = v.Name
	}

	// Compare leaf data to record content hashes to find duplicates
	var (
		// Dups tracks duplicates so we know which blobs should be
		// skipped when blobifying record content.
		dups = make(map[string]struct{}, 64)

		// Any duplicates that are found are added to the record index
		// since we already have the leaf data for them.
		index = recordIndex{
			Metadata: make(map[uint64][]byte, len(metadata)),
			Files:    make(map[string][]byte, len(files)),
		}
	)
	for _, v := range leavesAll {
		h := hex.EncodeToString(v.LeafValue)

		// Check record metadata
		if h == rhashes.recordMetadata {
			dups[h] = struct{}{}
			index.RecordMetadata = v.MerkleLeafHash
			continue
		}

		// Check metadata streams
		id, ok := rhashes.metadata[h]
		if ok {
			dups[h] = struct{}{}
			index.Metadata[id] = v.MerkleLeafHash
			continue
		}

		// Check files
		fn, ok := rhashes.files[h]
		if ok {
			dups[h] = struct{}{}
			index.Files[fn] = v.MerkleLeafHash
			continue
		}
	}

	// Prepare kv store blobs. The hashes of the record content are
	// also aggregated and will be used to create the log leaves that
	// are appended to the trillian tree.
	l := len(metadata) + len(files) + 1
	hashes := make([][]byte, 0, l)
	blobs := make([][]byte, 0, l)

	// Prepare record metadata blob
	be, err := convertBlobEntryFromRecordMetadata(recordMD)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	b, err = t.blobify(*be)
	if err != nil {
		return nil, err
	}
	_, ok := dups[be.Digest]
	if !ok {
		// Not a duplicate. Save blob to the store.
		hashes = append(hashes, h)
		blobs = append(blobs, b)
	}

	// Prepare metadata blobs
	for _, v := range metadata {
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Digest)
		if err != nil {
			return nil, err
		}
		b, err := t.blobify(*be)
		if err != nil {
			return nil, err
		}
		_, ok := dups[be.Digest]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	// Prepare file blobs
	for _, v := range files {
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Digest)
		if err != nil {
			return nil, err
		}
		b, err := t.blobify(*be)
		if err != nil {
			return nil, err
		}
		_, ok := dups[be.Digest]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	return &recordBlobsPrepareReply{
		recordIndex:  index,
		recordHashes: rhashes,
		blobs:        blobs,
		hashes:       hashes,
	}, nil
}

// recordBlobsSave saves the provided blobs to the kv store, appends a leaf
// to the trillian tree for each blob, then updates the record index with the
// trillian leaf information and returns it.
func (t *Tlog) recordBlobsSave(treeID int64, rbpr recordBlobsPrepareReply) (*recordIndex, error) {
	log.Tracef("recordBlobsSave: %v", t.id, treeID)

	var (
		index   = rbpr.recordIndex
		rhashes = rbpr.recordHashes
		blobs   = rbpr.blobs
		hashes  = rbpr.hashes
	)

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
		extraData := leafExtraData(dataTypeRecordContent, keys[k])
		leaves = append(leaves, newLogLeaf(hashes[k], extraData))
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

	// Update the new record index with the log leaves
	for _, v := range queued {
		// Figure out what piece of record content this leaf represents
		h := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)

		// Check record metadata
		if h == rhashes.recordMetadata {
			index.RecordMetadata = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Check metadata streams
		id, ok := rhashes.metadata[h]
		if ok {
			index.Metadata[id] = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Check files
		fn, ok := rhashes.files[h]
		if ok {
			index.Files[fn] = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Something went wrong. None of the record content matches the
		// leaf.
		return nil, fmt.Errorf("record content does not match leaf: %x",
			v.QueuedLeaf.Leaf.MerkleLeafHash)
	}

	return &index, nil
}

// RecordSave saves the provided record to tlog, creating a new version of the
// record (the record iteration also gets incremented on new versions). Once
// the record contents have been successfully saved to tlog, a recordIndex is
// created for this version of the record and saved to tlog as well.
func (t *Tlog) RecordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	log.Tracef("%v RecordSave: %v", t.id, treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll %v: %v", treeID, err)
	}

	// Get the existing record index
	currIdx, err := t.recordIndexLatest(leavesAll)
	if errors.Is(err, backend.ErrRecordNotFound) {
		// No record versions exist yet. This is ok.
		currIdx = &recordIndex{
			Metadata: make(map[uint64][]byte),
			Files:    make(map[string][]byte),
		}
	} else if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}

	// Verify tree state
	if currIdx.Frozen {
		return backend.ErrRecordLocked
	}

	// Prepare kv store blobs
	bpr, err := t.recordBlobsPrepare(leavesAll, rm, metadata, files)
	if err != nil {
		return err
	}

	// Verify file changes are being made.
	var fileChanges bool
	for _, v := range files {
		// Duplicate blobs have already been added to the new record
		// index by the recordBlobsPrepare function. If a file is in the
		// new record index it means that the file has existed in one of
		// the previous versions of the record.
		newMerkle, ok := bpr.recordIndex.Files[v.Name]
		if !ok {
			// File does not exist in the index. It is new.
			fileChanges = true
			break
		}

		// We now know the file has existed in a previous version of the
		// record, but it may not have be the most recent version. If the
		// file is not part of the current record index then it means
		// there are file changes between the current version and new
		// version.
		currMerkle, ok := currIdx.Files[v.Name]
		if !ok {
			// File is not part of the current version.
			fileChanges = true
			break
		}

		// We now know that the new file has existed in some previous
		// version of the record and the there is a file in the current
		// version of the record that has the same filename as the new
		// file. Check if the merkles match. If the merkles are different
		// then it means the files are different, they just use the same
		// filename.
		if !bytes.Equal(newMerkle, currMerkle) {
			// Files share the same name but have different content.
			fileChanges = true
			break
		}
	}
	if !fileChanges {
		return backend.ErrNoChanges
	}

	// Save blobs
	idx, err := t.recordBlobsSave(treeID, *bpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Bump the index version and iteration
	idx.Version = currIdx.Version + 1
	idx.Iteration = currIdx.Iteration + 1

	// Sanity checks
	switch {
	case idx.Version != currIdx.Version+1:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, currIdx.Version+1)
	case idx.Iteration != currIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, currIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(files):
		return fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(files))
	}

	// Save record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

// metadataSave saves the provided metadata to the kv store and trillian tree.
// The record index for this iteration of the record is returned. This is step
// one of a two step process. The record update will not be considered
// successful until the returned record index is also saved to the kv store and
// trillian tree. This code has been pulled out so that it can be called during
// normal metadata updates as well as when an update requires a freeze record
// to be saved along with the record index, such as when a record is censored.
func (t *Tlog) metadataSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) (*recordIndex, error) {
	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Verify tree state
	currIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return nil, err
	}
	if currIdx.Frozen {
		return nil, backend.ErrRecordLocked
	}

	// Prepare kv store blobs
	bpr, err := t.recordBlobsPrepare(leavesAll, rm, metadata, []backend.File{})
	if err != nil {
		return nil, err
	}

	// Verify at least one new blob is being saved to the kv store
	if len(bpr.blobs) == 0 {
		return nil, backend.ErrNoChanges
	}

	// Save the blobs
	idx, err := t.recordBlobsSave(treeID, *bpr)
	if err != nil {
		return nil, fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and add the unchanged fields to
	// the new record index. The version and files will remain the
	// same.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return nil, fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version
	idx.Files = oldIdx.Files

	// Increment the iteration
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check
	switch {
	case idx.Version != oldIdx.Version:
		return nil, fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version)
	case idx.Iteration != oldIdx.Iteration+1:
		return nil, fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return nil, fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return nil, fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(oldIdx.Files):
		return nil, fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(oldIdx.Files))
	}

	return idx, nil
}

// RecordMetadataSave saves the provided metadata to tlog, creating a new
// iteration of the record while keeping the record version the same. Once the
// metadata has been successfully saved to tlog, a recordIndex is created for
// this iteration of the record and saved to tlog as well.
func (t *Tlog) RecordMetadataSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	log.Tracef("%v RecordMetadataSave: %v", t.id, treeID)

	// Save metadata
	idx, err := t.metadataSave(treeID, rm, metadata)
	if err != nil {
		return err
	}

	// Save record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

// RecordDel walks the provided tree and deletes all file blobs in the store
// that correspond to record files. This is done for all versions and all
// iterations of the record. Record metadata and metadata stream blobs are not
// deleted.
func (t *Tlog) RecordDel(treeID int64) error {
	log.Tracef("%v RecordDel: %v", t.id, treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return backend.ErrRecordNotFound
	}

	// Get all tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
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

	// Retrieve all the record indexes
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

// RecordExists returns whether a record exists on the provided tree ID. A
// record is considered to not exist if any of the following conditions are
// met:
//
// * A tree does not exist for the tree ID.
//
// * A tree exists but a record index does not exist. This can happen if a
//   tree was created but there was a network error prior to the record index
//   being appended to the tree.
//
// * The tree is frozen and points to another tree. The record is considered to
//   exists on the tree being pointed to, but not on this one. This happens
//   in some situations like when an unvetted record is made public and copied
//   onto a vetted tree.
//
// The tree pointer is also returned if one is found.
func (t *Tlog) RecordExists(treeID int64) bool {
	log.Tracef("%v RecordExists: %v", t.id, treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return false
	}

	// Verify record index exists
	var idx *recordIndex
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		err = fmt.Errorf("leavesAll: %v", err)
		goto printErr
	}
	idx, err = t.recordIndexLatest(leavesAll)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			// This is an empty tree. This can happen sometimes if a error
			// occurred during record creation. Return gracefully.
			return false
		}
		err = fmt.Errorf("recordIndexLatest: %v", err)
		goto printErr
	}

	// Verify a tree pointer does not exist
	if treePointerExists(*idx) {
		return false
	}

	// Record exists!
	return true

printErr:
	log.Errorf("%v RecordExists: %v", t.id, err)
	return false
}

func (t *Tlog) Record(treeID int64, version uint32) (*backend.Record, error) {
	log.Tracef("%v record: %v %v", t.id, treeID, version)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
	}

	// Verify the latest record index does not point to another tree.
	// If it does have a tree pointer, the record is considered to
	// exists on the tree being pointed to, but not on this one. This
	// happens in situations such as when an unvetted record is made
	// public and copied to a vetted tree. Querying the unvetted tree
	// will result in a backend.ErrRecordNotFound error being returned
	// and the vetted tree must be queried instead.
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return nil, err
	}
	idxLatest, err := parseRecordIndex(indexes, 0)
	if err != nil {
		return nil, err
	}
	if treePointerExists(*idxLatest) {
		return nil, backend.ErrRecordNotFound
	}

	// Use the record index to pull the record content from the store.
	// The keys for the record content first need to be extracted from
	// their associated log leaf.
	idx, err := parseRecordIndex(indexes, version)
	if err != nil {
		return nil, err
	}

	// Compile merkle root hashes of record content
	merkles := make(map[string]struct{}, 64)
	merkles[hex.EncodeToString(idx.RecordMetadata)] = struct{}{}
	for _, v := range idx.Metadata {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}
	for _, v := range idx.Files {
		merkles[hex.EncodeToString(v)] = struct{}{}
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
		keys = append(keys, extractKeyFromLeaf(v))
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
		be, err := t.deblob(v)
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

	// Sanity checks
	switch {
	case recordMD == nil:
		return nil, fmt.Errorf("record metadata not found")
	case len(metadata) != len(idx.Metadata):
		return nil, fmt.Errorf("invalid number of metadata; got %v, want %v",
			len(metadata), len(idx.Metadata))
	}

	return &backend.Record{
		Version:        strconv.FormatUint(uint64(idx.Version), 10),
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

func (t *Tlog) RecordLatest(treeID int64) (*backend.Record, error) {
	log.Tracef("%v RecordLatest: %v", t.id, treeID)
	return t.Record(treeID, 0)
}

func (t *Tlog) timestamp(treeID int64, merkleLeafHash []byte, leaves []*trillian.LogLeaf) (*backend.Timestamp, error) {
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
	key := extractKeyFromLeaf(l)
	blobs, err := t.store.Get([]string{key})
	if err != nil {
		return nil, fmt.Errorf("store get: %v", err)
	}

	// Extract the data blob. Its possible for the data blob to not
	// exist if has been censored. This is ok. We'll still return the
	// rest of the timestamp.
	var data []byte
	if len(blobs) == 1 {
		b, ok := blobs[key]
		if !ok {
			return nil, fmt.Errorf("blob not found %v", key)
		}
		be, err := t.deblob(b)
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
	p, err := t.trillian.inclusionProof(treeID, l.MerkleLeafHash, a.LogRoot)
	if err != nil {
		return nil, fmt.Errorf("inclusionProof %v %x: %v",
			treeID, l.MerkleLeafHash, err)
	}

	// Setup proof for data digest inclusion in the log merkle root
	ed := ExtraDataTrillianRFC6962{
		LeafIndex: p.LeafIndex,
		TreeSize:  int64(a.LogRoot.TreeSize),
	}
	extraData, err := json.Marshal(ed)
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
	hashes := a.VerifyDigest.ChainInformation.MerklePath.Hashes
	merklePath = make([]string, 0, len(hashes))
	for _, v := range hashes {
		merklePath = append(merklePath, hex.EncodeToString(v[:]))
	}
	dcrtimeProof := backend.Proof{
		Type:       ProofTypeDcrtime,
		Digest:     a.VerifyDigest.Digest,
		MerkleRoot: a.VerifyDigest.ChainInformation.MerkleRoot,
		MerklePath: merklePath,
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

func (t *Tlog) RecordTimestamps(treeID int64, version uint32, token []byte) (*backend.RecordTimestamps, error) {
	log.Tracef("%v RecordTimestamps: %v %v", t.id, treeID, version)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get record index
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
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
	metadata := make(map[uint64]backend.Timestamp, len(idx.Metadata))
	for k, v := range idx.Metadata {
		ts, err := t.timestamp(treeID, v, leaves)
		if err != nil {
			return nil, fmt.Errorf("metadata %v timestamp: %v", k, err)
		}
		metadata[k] = *ts
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
		Token:          hex.EncodeToString(token),
		Version:        strconv.FormatUint(uint64(version), 10),
		RecordMetadata: *rm,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

// TODO run fsck episodically
func (t *Tlog) Fsck() {
	// Set tree status to frozen for any trees that are frozen and have
	// been anchored one last time.
	// Failed censor. Ensure all blobs have been deleted from all
	// record versions of a censored record.
}

func (t *Tlog) Close() {
	log.Tracef("%v Close", t.id)

	// Close connections
	t.store.Close()
	t.trillian.close()

	// Zero out encryption key. An encryption key is optional.
	if t.encryptionKey != nil {
		t.encryptionKey.zero()
	}
}

func New(id, homeDir, dataDir string, anp *chaincfg.Params, trillianHost, trillianKeyFile, encryptionKeyFile, dcrtimeHost, dcrtimeCert string) (*Tlog, error) {
	// Load encryption key if provided. An encryption key is optional.
	var ek *encryptionKey
	if encryptionKeyFile != "" {
		f, err := os.Open(encryptionKeyFile)
		if err != nil {
			return nil, err
		}
		var key [32]byte
		n, err := f.Read(key[:])
		if n != len(key) {
			return nil, fmt.Errorf("invalid encryption key length")
		}
		if err != nil {
			return nil, err
		}
		f.Close()
		ek = newEncryptionKey(&key)

		log.Infof("Encryption key %v: %v", id, encryptionKeyFile)
	}

	// Setup datadir for this tlog instance
	dataDir = filepath.Join(dataDir, id)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup key-value store
	fp := filepath.Join(dataDir, defaultStoreDirname)
	err = os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	// Setup trillian client
	if trillianKeyFile == "" {
		// No file path was given. Use the default path.
		fn := fmt.Sprintf("%v-%v", id, defaultTrillianKeyFilename)
		trillianKeyFile = filepath.Join(homeDir, fn)
	}

	log.Infof("Trillian key %v: %v", id, trillianKeyFile)
	log.Infof("Trillian host %v: %v", id, trillianHost)

	trillianClient, err := newTClient(trillianHost, trillianKeyFile)
	if err != nil {
		return nil, err
	}

	// Setup dcrtime client
	dcrtimeClient, err := newDcrtimeClient(dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, err
	}

	// Setup tlog
	t := Tlog{
		id:              id,
		dataDir:         dataDir,
		activeNetParams: anp,
		trillian:        trillianClient,
		store:           store,
		dcrtime:         dcrtimeClient,
		cron:            cron.New(),
		encryptionKey:   ek,
	}

	// Launch cron
	log.Infof("Launch %v cron anchor job", id)
	err = t.cron.AddFunc(anchorSchedule, func() {
		t.anchorTrees()
	})
	if err != nil {
		return nil, err
	}
	t.cron.Start()

	return &t, nil
}
