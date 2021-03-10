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
	"github.com/google/uuid"
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
	dataDescriptorRecordMetadata = "pd-recordmd-v1"
	dataDescriptorMetadataStream = "pd-mdstream-v1"
	dataDescriptorFile           = "pd-file-v1"
	dataDescriptorRecordIndex    = "pd-rindex-v1"
	dataDescriptorAnchor         = "pd-anchor-v1"

	// keyPrefixEncrypted is prefixed onto key-value store keys if the
	// data is encrypted. We do this so that when a record is made
	// public we can save the plain text record content blobs using the
	// same keys, but without the prefix. Using a new key for the plain
	// text blobs would not work since we cannot append a new leaf onto
	// the tlog without getting a duplicate leaf error.
	keyPrefixEncrypted = "e_"
)

var (
	_ plugins.TstoreClient = (*Tstore)(nil)
)

// We do not unwind.
type Tstore struct {
	sync.Mutex
	dataDir         string
	activeNetParams *chaincfg.Params
	tlog            tlogClient
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
	isEncrypted := bytes.HasPrefix(b, []byte("sbox"))
	log.Tracef("Blob is encrypted: %v", isEncrypted)
	return isEncrypted
}

// extraData is the data that is stored in the log leaf ExtraData field. It is
// saved as a JSON encoded byte slice. The JSON keys have been abbreviated to
// minimize the size of a trillian log leaf.
type extraData struct {
	// Key contains the key-value store key. If this blob is part of an
	// unvetted record the key will need to be prefixed with the
	// keyPrefixEncrypted in order to retrieve the blob from the kv
	// store. Use the extraData.storeKey() method to retrieve the key.
	// Do NOT reference this key directly.
	Key string `json:"k"`

	// Desc contains the blob entry data descriptor.
	Desc string `json:"d"`

	// State indicates the record state of the blob that this leaf
	// corresponds to. Unvetted blobs encrypted prior to being saved
	// to the store. When retrieving unvetted blobs from the kv store
	// the keyPrefixEncrypted prefix must be added to the Key field.
	// State will not be populated for anchor records.
	State backend.StateT `json:"s,omitempty"`
}

// storeKey returns the kv store key for the blob. If the blob is part of an
// unvetted record it will be saved as an encrypted blob in the kv store and
// the key is prefixed with keyPrefixEncrypted.
func (e *extraData) storeKey() string {
	if e.State == backend.StateUnvetted {
		return keyPrefixEncrypted + e.Key
	}
	return e.Key
}

// storeKeyNoPrefix returns the kv store key without any encryption prefix,
// even if the leaf corresponds to a unvetted blob.
func (e *extraData) storeKeyNoPrefix() string {
	return e.Key
}

func extraDataEncode(key, desc string, state backend.StateT) ([]byte, error) {
	// The encryption prefix is stripped from the key if one exists.
	ed := extraData{
		Key:   storeKeyClean(key),
		Desc:  desc,
		State: state,
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

// storeKeyNew returns a new key for the key-value store. If the data is
// encrypted the key is prefixed.
func storeKeyNew(encrypt bool) string {
	k := uuid.New().String()
	if encrypt {
		k = keyPrefixEncrypted + k
	}
	return k
}

// storeKeyClean strips the key-value store key of the encryption prefix if
// one is present.
func storeKeyClean(key string) string {
	// A uuid string is 36 bytes. Return the last 36 bytes of the
	// string. This will strip the prefix if it exists.
	return key[len(key)-36:]
}

func merkleLeafHashForBlobEntry(be store.BlobEntry) ([]byte, error) {
	leafValue, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	return merkleLeafHash(leafValue), nil
}

func (t *Tstore) blobify(be store.BlobEntry, encrypt bool) ([]byte, error) {
	b, err := store.Blobify(be)
	if err != nil {
		return nil, err
	}
	if encrypt {
		b, err = t.encryptionKey.encrypt(0, b)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (t *Tstore) deblob(b []byte) (*store.BlobEntry, error) {
	var err error
	if blobIsEncrypted(b) {
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

	tree, _, err := t.tlog.treeNew()
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
func (t *Tstore) TreeFreeze(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	log.Tracef("TreeFreeze: %v", treeID)

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

// TreesAll returns the IDs of all trees in the tstore instance.
func (t *Tstore) TreesAll() ([]int64, error) {
	trees, err := t.tlog.treesAll()
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
	_, err := t.tlog.tree(treeID)
	return err == nil
}

func (t *Tstore) treeIsFrozen(leaves []*trillian.LogLeaf) bool {
	r, err := t.recordIndexLatest(leaves)
	if err != nil {
		panic(err)
	}
	return r.Frozen
}

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

		encrypt bool
	)

	// Only vetted data should be saved plain text
	switch idx.State {
	case backend.StateUnvetted:
		encrypt = true
	case backend.StateVetted:
		// Save plain text
		encrypt = false
	default:
		// Something is wrong
		e := fmt.Sprintf("invalid record state %v %v", treeID, idx.State)
		panic(e)
	}

	// Prepare record metadata blobs and leaves
	_, ok := dups[beRecordMD.Digest]
	if !ok {
		// Not a duplicate. Prepare kv store blob.
		b, err := t.blobify(*beRecordMD, encrypt)
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
			if !ok {
				// Not a duplicate. Prepare kv store blob.
				b, err := t.blobify(be, encrypt)
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

				continue
			}

			// This is a duplicate. Stash is for now. We may need to save
			// it as plain text later.
			dupBlobs[be.Digest] = be
		}
	}

	// Prepare file blobs and leaves
	for _, be := range beFiles {
		_, ok := dups[be.Digest]
		if !ok {
			// Not a duplicate. Prepare kv store blob.
			b, err := t.blobify(be, encrypt)
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

			continue
		}

		// This is a duplicate. Stash is for now. We may need to save
		// it as plain text later.
		dupBlobs[be.Digest] = be
	}

	// Verify at least one new blob is being saved to the kv store
	if len(blobs) == 0 {
		return nil, backend.ErrNoRecordChanges
	}

	log.Debugf("Saving %v record content blobs", len(blobs))

	// Save blobs to the kv store
	err = t.store.Put(blobs)
	if err != nil {
		return nil, fmt.Errorf("store PutKV: %v", err)
	}

	// Append leaves onto the trillian tree
	queued, _, err := t.tlog.leavesAppend(treeID, leaves)
	if err != nil {
		return nil, fmt.Errorf("leavesAppend: %v", err)
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

	// Check if any of the duplicates were saved as encrypted but now
	// need to be resaved as plain text. This happens when a record is
	// made public and the files need to be saved plain text.
	if idx.State == backend.StateUnvetted || len(dups) == 0 {
		// Nothing that needs to be saved plain text. We're done.
		log.Tracef("No blobs need to be resaved plain text")

		return &idx, nil
	}

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
		b, err := t.blobify(be, false)
		if err != nil {
			return nil, err
		}
		blobs[ed.storeKeyNoPrefix()] = b
	}
	if len(blobs) == 0 {
		// Nothing that needs to be saved plain text. We're done.
		log.Tracef("No duplicates need to be resaved plain text")

		return &idx, nil
	}

	log.Debugf("Resaving %v encrypted blobs as plain text", len(blobs))

	err = t.store.Put(blobs)
	if err != nil {
		return nil, fmt.Errorf("store PutKV: %v", err)
	}

	return &idx, nil
}

func (t *Tstore) recordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) (*recordIndex, error) {
	// Verify tree exists
	if !t.TreeExists(treeID) {
		return nil, backend.ErrRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
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
// version of the record and saved to tstore as well. This iteration of the
// record is not considered to be valid until the record index has been
// successfully saved.
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
	leavesAll, err := t.tlog.leavesAll(treeID)
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
	leaves, err := t.tlog.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
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
	p, err := t.tlog.inclusionProof(treeID, l.MerkleLeafHash, a.LogRoot)
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
	leaves, err := t.tlog.leavesAll(treeID)
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
	t.tlog.close()

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

	tlogClient, err := newTClient(trillianHost, trillianSigningKeyFile)
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
		tlog:            tlogClient,
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
