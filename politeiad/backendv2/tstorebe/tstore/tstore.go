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
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/mysql"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/marcopeereboom/sbox"
	"github.com/robfig/cron"
	"google.golang.org/grpc/codes"
)

const (
	DBTypeLevelDB = "leveldb"
	DBTypeMySQL   = "mysql"
	dbUser        = "politeiad"

	defaultEncryptionKeyFilename      = "tstore-sbox.key"
	defaultTrillianSigningKeyFilename = "trillian.key"
	defaultStoreDirname               = "store"

	// Blob entry data descriptors
	dataDescriptorFile           = "pd-file-v1"
	dataDescriptorRecordMetadata = "pd-recordmd-v1"
	dataDescriptorMetadataStream = "pd-mdstream-v1"
	dataDescriptorRecordIndex    = "pd-rindex-v1"
	dataDescriptorAnchor         = "pd-anchor-v1"
)

var (
	_ plugins.TstoreClient = (*Tstore)(nil)
)

// We do not unwind.
type Tstore struct {
	sync.Mutex
	dataDir         string
	activeNetParams *chaincfg.Params
	trillian        trillianClient
	store           store.BlobKV
	dcrtime         *dcrtimeClient
	cron            *cron.Cron
	plugins         map[string]plugin // [pluginID]plugin

	// encryptionKey is used to encrypt record blobs before saving them
	// to the key-value store. This is an optional param. Record blobs
	// will not be encrypted if this is left as nil.
	encryptionKey *encryptionKey

	// droppingAnchor indicates whether tstore is in the process of
	// dropping an anchor, i.e. timestamping unanchored trillian trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool
}

// blobIsEncrypted returns whether the provided blob has been prefixed with an
// sbox header, indicating that it is an encrypted blob.
func blobIsEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}

// extraData is the data that is stored in the log leaf ExtraData field. It is
// saved as a JSON encoded byte slice. The JSON keys have been abbreviated to
// minimize the size of a trillian log leaf.
type extraData struct {
	Key  string `json:"k"` // Key-value store key
	Desc string `json:"d"` // Blob entry data descriptor
}

func extraDataEncode(key, desc string) ([]byte, error) {
	ed := extraData{
		Key:  key,
		Desc: desc,
	}
	b, err := json.Marshal(ed)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func extraDataDecode(b []byte) (*extraData, error) {
	var ed extraData
	err := json.Unmarshal(b, &ed)
	if err != nil {
		return nil, err
	}
	return &ed, nil
}

func (t *Tstore) blobify(be store.BlobEntry) ([]byte, error) {
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

func (t *Tstore) deblob(b []byte) (*store.BlobEntry, error) {
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

func (t *Tstore) TreeNew() (int64, error) {
	log.Tracef("TreeNew")

	tree, _, err := t.trillian.treeNew()
	if err != nil {
		return 0, err
	}

	return tree.TreeId, nil
}

// TreeFreeze updates the status of a record then freezes the trillian tree to
// prevent any additional updates.
//
// A tree is considered to be frozen once the record index has been saved with
// its Frozen field set to true. The only thing that can be appended onto a
// frozen tree is one additional anchor record. Once a frozen tree has been
// anchored, the tstore fsck function will update the status of the tree to
// frozen in trillian, at which point trillian will prevent any changes to the
// tree.
func (t *Tstore) TreeFreeze(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	log.Tracef("TreeFreeze: %v", treeID)

	// Save metadata
	idx, err := t.metadataSave(treeID, rm, metadata)
	if err != nil {
		return err
	}

	// Update the record index
	idx.Frozen = true

	// Save the record index
	return t.recordIndexSave(treeID, *idx)
}

// TreesAll returns the IDs of all trees in the tstore instance.
func (t *Tstore) TreesAll() ([]int64, error) {
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

// TreeExists returns whether a tree exists in the trillian log. A tree
// existing doesn't necessarily mean that a record exists. Its possible for a
// tree to have been created but experienced an unexpected error prior to the
// record being saved.
func (t *Tstore) TreeExists(treeID int64) bool {
	_, err := t.trillian.tree(treeID)
	return err == nil
}

func (t *Tstore) treeIsFrozen(leaves []*trillian.LogLeaf) bool {
	r, err := t.recordIndexLatest(leaves)
	if err != nil {
		panic(err)
	}
	return r.Frozen
}

type recordHashes struct {
	recordMetadata string                            // Record metadata hash
	metadata       map[string]backend.MetadataStream // [hash]MetadataStream
	files          map[string]backend.File           // [hash]File
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
	// saved to the kv store.
	//
	// Hashes contains the hashes of the record content prior to being
	// blobified. These hashes are saved to trilian log leaves. The
	// hashes are SHA256 hashes of the JSON encoded data.
	//
	// hints contains the data hints of the blob entries.
	//
	// blobs, hashes, and descriptors share the same ordering.
	blobs  [][]byte
	hashes [][]byte
	hints  []string
}

// recordBlobsPrepare prepares the provided record content to be saved to
// the blob kv store and appended onto a trillian tree.
func (t *Tstore) recordBlobsPrepare(leavesAll []*trillian.LogLeaf, recordMD backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) (*recordBlobsPrepareReply, error) {
	// Verify there are no duplicate or empty mdstream IDs
	md := make(map[string]map[uint32]struct{}, len(metadata))
	for _, v := range metadata {
		if v.StreamID == 0 {
			return nil, fmt.Errorf("invalid metadata stream ID 0")
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
		// [hash]MetadataStream
		metadata: make(map[string]backend.MetadataStream, len(metadata)),

		// [hash]File
		files: make(map[string]backend.File, len(files)),
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
		rhashes.metadata[h] = v
	}
	for _, v := range files {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.files[h] = v
	}

	// Compare leaf data to record content hashes to find duplicates
	var (
		// Dups tracks duplicates so we know which blobs should be
		// skipped when blobifying record content.
		dups = make(map[string]struct{}, 64)

		// Any duplicates that are found are added to the record index
		// since we already have the leaf data for them.
		index = recordIndex{
			Metadata: make(map[string]map[uint32][]byte, len(metadata)),
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
		ms, ok := rhashes.metadata[h]
		if ok {
			dups[h] = struct{}{}
			streams, ok := index.Metadata[ms.PluginID]
			if !ok {
				streams = make(map[uint32][]byte, 64)
			}
			streams[ms.StreamID] = v.MerkleLeafHash
			index.Metadata[ms.PluginID] = streams
			continue
		}

		// Check files
		f, ok := rhashes.files[h]
		if ok {
			dups[h] = struct{}{}
			index.Files[f.Name] = v.MerkleLeafHash
			continue
		}
	}

	// Prepare kv store blobs. The hashes of the record content are
	// also aggregated and will be used to create the log leaves that
	// are appended to the trillian tree.
	l := len(metadata) + len(files) + 1
	hashes := make([][]byte, 0, l)
	blobs := make([][]byte, 0, l)
	hints := make([]string, 0, l)

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
		hints = append(hints, be.DataHint)
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
			hints = append(hints, be.DataHint)
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
			hints = append(hints, be.DataHint)
		}
	}

	return &recordBlobsPrepareReply{
		recordIndex:  index,
		recordHashes: rhashes,
		blobs:        blobs,
		hashes:       hashes,
		hints:        hints,
	}, nil
}

// recordBlobsSave saves the provided blobs to the kv store, appends a leaf
// to the trillian tree for each blob, then updates the record index with the
// trillian leaf information and returns it.
func (t *Tstore) recordBlobsSave(treeID int64, rbpr recordBlobsPrepareReply) (*recordIndex, error) {
	log.Tracef("recordBlobsSave: %v", treeID)

	var (
		index   = rbpr.recordIndex
		rhashes = rbpr.recordHashes
		blobs   = rbpr.blobs
		hashes  = rbpr.hashes
		hints   = rbpr.hints
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
		extraData, err := extraDataEncode(keys[k], hints[k])
		if err != nil {
			return nil, err
		}
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
		ms, ok := rhashes.metadata[h]
		if ok {
			streams, ok := index.Metadata[ms.PluginID]
			if !ok {
				streams = make(map[uint32][]byte, 64)
			}
			streams[ms.StreamID] = v.QueuedLeaf.Leaf.MerkleLeafHash
			index.Metadata[ms.PluginID] = streams
			continue
		}

		// Check files
		f, ok := rhashes.files[h]
		if ok {
			index.Files[f.Name] = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Something went wrong. None of the record content matches the
		// leaf.
		return nil, fmt.Errorf("record content does not match leaf: %x",
			v.QueuedLeaf.Leaf.MerkleLeafHash)
	}

	return &index, nil
}

// RecordSave saves the provided record to tstore. Once the record contents
// have been successfully saved to tstore, a recordIndex is created for this
// version of the record and saved to tstore as well. This iteration of the
// record is not considered to be valid until the record index has been
// successfully saved.
func (t *Tstore) RecordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	log.Tracef("RecordSave: %v", treeID)

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
			Metadata: make(map[string]map[uint32][]byte),
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
		return backend.ErrNoRecordChanges
	}

	// Save blobs
	idx, err := t.recordBlobsSave(treeID, *bpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Bump the index version and iteration
	idx.Version = rm.Version
	idx.Iteration = rm.Iteration

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

// metadataSave saves the provided metadata to the tstore. The record index
// for this iteration of the record is returned. This is step one of a two step
// process. The record update will not be considered successful until the
// returned record index is also saved to the kv store and trillian tree. This
// code has been pulled out so that it can be called during normal metadata
// updates as well as when an update requires the tree to be frozen, such as
// when a record is censored.
func (t *Tstore) metadataSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) (*recordIndex, error) {
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
		return nil, backend.ErrNoRecordChanges
	}

	// Save the blobs
	idx, err := t.recordBlobsSave(treeID, *bpr)
	if err != nil {
		return nil, fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and add the unchanged fields to
	// the new record index.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return nil, fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = rm.Version
	idx.Files = oldIdx.Files

	// Update the version and iteration
	idx.Version = rm.Version
	idx.Iteration = rm.Iteration

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

// RecordMetadataSave saves the provided metadata to tstore, creating a new
// iteration of the record while keeping the record version the same. Once the
// metadata has been successfully saved to tstore, a recordIndex is created for
// this iteration of the record and saved to tstore as well.
func (t *Tstore) RecordMetadataSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	log.Tracef("RecordMetadataSave: %v", treeID)

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
func (t *Tstore) RecordDel(treeID int64) error {
	log.Tracef("RecordDel: %v", treeID)

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

// RecordExists returns whether a record exists given a trillian tree ID. A
// record is considered to not exist if any of the following conditions are
// met:
//
// * A tree does not exist for the tree ID.
//
// * A tree exists but a record index does not exist. This can happen if a
//   tree was created but there was an unexpected error prior to the record
//   index being appended to the tree.
func (t *Tstore) RecordExists(treeID int64) bool {
	log.Tracef("RecordExists: %v", treeID)

	// Verify tree exists
	if !t.TreeExists(treeID) {
		return false
	}

	// Verify record index exists
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		err = fmt.Errorf("leavesAll: %v", err)
		goto printErr
	}
	_, err = t.recordIndexLatest(leavesAll)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			// This is an empty tree. This can happen sometimes if a error
			// occurred during record creation. Return gracefully.
			return false
		}
		err = fmt.Errorf("recordIndexLatest: %v", err)
		goto printErr
	}

	// Record exists!
	return true

printErr:
	log.Errorf("RecordExists: %v", err)
	return false
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
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
	}

	// Use the record index to pull the record content from the store.
	// The keys for the record content first need to be extracted from
	// their log leaf.
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return nil, err
	}
	idx, err := parseRecordIndex(indexes, version)
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
		keys = append(keys, ed.Key)
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
	blobs, err := t.store.Get([]string{ed.Key})
	if err != nil {
		return nil, fmt.Errorf("store get: %v", err)
	}

	// Extract the data blob. Its possible for the data blob to not
	// exist if it has been censored. This is ok. We'll still return
	// the rest of the timestamp.
	var data []byte
	if len(blobs) == 1 {
		b, ok := blobs[ed.Key]
		if !ok {
			return nil, fmt.Errorf("blob not found %v", ed.Key)
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

func (t *Tstore) RecordTimestamps(treeID int64, version uint32, token []byte) (*backend.RecordTimestamps, error) {
	log.Tracef("RecordTimestamps: %v %v", treeID, version)

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

func (t *Tstore) Fsck() {
	// Set tree status to frozen for any trees that are frozen and have
	// been anchored one last time.
	// Failed censor. Ensure all blobs have been deleted from all
	// record versions of a censored record.
}

func (t *Tstore) Close() {
	log.Tracef("Close")

	// Close connections
	t.store.Close()
	t.trillian.close()

	// Zero out encryption key. An encryption key is optional.
	if t.encryptionKey != nil {
		t.encryptionKey.zero()
	}
}

func New(appDir, dataDir string, anp *chaincfg.Params, trillianHost, trillianSigningKeyFile, dbType, dbHost, dbPass, dbEncryptionKeyFile, dcrtimeHost, dcrtimeCert string) (*Tstore, error) {
	// Setup encryption key file
	if dbEncryptionKeyFile == "" {
		// No file path was given. Use the default path.
		dbEncryptionKeyFile = filepath.Join(appDir, defaultEncryptionKeyFilename)
	}
	if !util.FileExists(dbEncryptionKeyFile) {
		// Encryption key file does not exist. Create one.
		log.Infof("Generating encryption key")
		key, err := sbox.NewKey()
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(dbEncryptionKeyFile, key[:], 0400)
		if err != nil {
			return nil, err
		}
		util.Zero(key[:])
		log.Infof("Encryption key created: %v", dbEncryptionKeyFile)
	}

	// Load encryption key
	f, err := os.Open(dbEncryptionKeyFile)
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
	ek := newEncryptionKey(&key)

	log.Infof("Encryption key: %v", dbEncryptionKeyFile)

	// Setup trillian client
	if trillianSigningKeyFile == "" {
		// No file path was given. Use the default path.
		fn := fmt.Sprintf("%v", defaultTrillianSigningKeyFilename)
		trillianSigningKeyFile = filepath.Join(appDir, fn)
	}

	log.Infof("Trillian key: %v", trillianSigningKeyFile)
	log.Infof("Trillian host: %v", trillianHost)

	trillianClient, err := newTClient(trillianHost, trillianSigningKeyFile)
	if err != nil {
		return nil, err
	}

	// Setup datadir for this tstore instance
	dataDir = filepath.Join(dataDir)
	err = os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup key-value store
	log.Infof("Database type: %v", dbType)
	var kvstore store.BlobKV
	switch dbType {
	case DBTypeLevelDB:
		fp := filepath.Join(dataDir, defaultStoreDirname)
		err = os.MkdirAll(fp, 0700)
		if err != nil {
			return nil, err
		}
		kvstore, err = localdb.New(fp)
		if err != nil {
			return nil, err
		}
	case DBTypeMySQL:
		// Example db name: testnet3_unvetted_kv
		dbName := fmt.Sprintf("%v_kv", anp.Name)
		kvstore, err = mysql.New(dbHost, dbUser, dbPass, dbName)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid db type: %v", dbType)
	}

	// Verify dcrtime host
	_, err = url.Parse(dcrtimeHost)
	if err != nil {
		return nil, fmt.Errorf("parse dcrtime host '%v': %v", dcrtimeHost, err)
	}
	log.Infof("Anchor host: %v", dcrtimeHost)

	// Setup dcrtime client
	dcrtimeClient, err := newDcrtimeClient(dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, err
	}

	// Setup tstore
	t := Tstore{
		dataDir:         dataDir,
		activeNetParams: anp,
		trillian:        trillianClient,
		store:           kvstore,
		dcrtime:         dcrtimeClient,
		cron:            cron.New(),
		plugins:         make(map[string]plugin),
		encryptionKey:   ek,
	}

	// Launch cron
	log.Infof("Launch cron anchor job")
	err = t.cron.AddFunc(anchorSchedule, func() {
		err := t.anchorTrees()
		if err != nil {
			log.Errorf("anchorTrees: %v", err)
		}
	})
	if err != nil {
		return nil, err
	}
	t.cron.Start()

	return &t, nil
}
