// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/robfig/cron"
	"google.golang.org/grpc/codes"
)

const (
	// Blob entry data descriptors
	dataDescriptorFile           = "file"
	dataDescriptorRecordMetadata = "recordmetadata"
	dataDescriptorMetadataStream = "metadatastream"
	dataDescriptorRecordIndex    = "recordindex"
	dataDescriptorFreezeRecord   = "freezerecord"

	// The keys for kv store blobs are saved by stuffing them into the
	// ExtraData field of their corresponding trillian log leaf. The
	// keys are prefixed with one of the follwing identifiers before
	// being added to the log leaf so that we can correlate the leaf
	// to the type of data it represents without having to pull the
	// data out of the store, which can become an issue in situations
	// such as searching for a record index that has been buried by
	// thousands of leaves from plugin data.
	keyPrefixRecordIndex   = "index:"
	keyPrefixRecordContent = "record:"
	keyPrefixFreezeRecord  = "freeze:"
)

var (
	// errRecordNotFound is emitted when a record is not found.
	errRecordNotFound = errors.New("record not found")

	errFreezeRecordNotFound = errors.New("freeze record not found")

	// errNoFileChanges is emitted when a new version of a record is
	// attemtepd to be saved with no changes to the files.
	errNoFileChanges = errors.New("no file changes")

	// errNoMetadataChanges is emitted when there are no metadata
	// changes being made on a metadata update.
	errNoMetadataChanges = errors.New("no metadata changes")
)

// We do not unwind.
type tlog struct {
	dataDir       string
	encryptionKey *EncryptionKey
	client        *TrillianClient
	store         store.Blob_

	// TODO implement anchoring
	dcrtimeHost string
	cron        *cron.Cron

	// droppingAnchor indicates whether tlogbe is in the process of
	// dropping an anchor, i.e. timestamping unanchored trillian trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool
}

type recordIndex struct {
	// Version represents the version of the record. The version is
	// only incremented when the record files are updated.
	Version uint32 `json:"version"`

	// Iteration represents the iteration of the record. The iteration
	// is incremented anytime any record content changes. This includes
	// file changes that bump the version as well metadata stream and
	// record metadata changes that don't bump the version.
	//
	// Note this is not the same as the RecordMetadata iteration, which
	// does not get incremented on metadata stream updates.
	Iteration uint32 `json:"iteration"`

	// The following fields contain the merkle leaf hashes of the
	// trillian log leaves for the record content. The merkle leaf hash
	// can be used to lookup the log leaf. The log leaf ExtraData field
	// contains the key for the record content in the key-value store.
	RecordMetadata []byte            `json:"recordmetadata"`
	Metadata       map[uint64][]byte `json:"metadata"` // [metadataID]merkle
	Files          map[string][]byte `json:"files"`    // [filename]merkle
}

type freezeRecord struct {
	TreeID int64 `json:"treeid,omitempty"`
}

func treeIDFromToken(token []byte) int64 {
	return int64(binary.LittleEndian.Uint64(token))
}

func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	// Converting between int64 and uint64 doesn't change the sign bit,
	// only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

// isEncrypted returns whether the provided blob has been prefixed with an
// sbox header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}

func isRecordIndexLeaf(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixRecordIndex))
}

func isRecordContentLeaf(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixRecordContent))
}

func isFreezeRecordLeaf(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixFreezeRecord))
}

func extractKeyForRecordIndex(l *trillian.LogLeaf) (string, error) {
	s := bytes.SplitAfter(l.ExtraData, []byte(keyPrefixRecordIndex))
	if len(s) != 2 {
		return "", fmt.Errorf("invalid key %s", l.ExtraData)
	}
	return string(s[1]), nil
}

func extractKeyForRecordContent(l *trillian.LogLeaf) (string, error) {
	s := bytes.SplitAfter(l.ExtraData, []byte(keyPrefixRecordContent))
	if len(s) != 2 {
		return "", fmt.Errorf("invalid key %s", l.ExtraData)
	}
	return string(s[1]), nil
}

func extractKeyForFreezeRecord(l *trillian.LogLeaf) (string, error) {
	s := bytes.SplitAfter(l.ExtraData, []byte(keyPrefixFreezeRecord))
	if len(s) != 2 {
		return "", fmt.Errorf("invalid key %s", l.ExtraData)
	}
	return string(s[1]), nil
}

func convertBlobEntryFromFile(f backend.File) (*blobEntry, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorFile,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromMetadataStream(ms backend.MetadataStream) (*blobEntry, error) {
	data, err := json.Marshal(ms)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorMetadataStream,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromRecordMetadata(rm backend.RecordMetadata) (*blobEntry, error) {
	data, err := json.Marshal(rm)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorRecordMetadata,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromRecordIndex(ri recordIndex) (*blobEntry, error) {
	data, err := json.Marshal(ri)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorRecordIndex,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromFreezeRecord(fr freezeRecord) (*blobEntry, error) {
	data, err := json.Marshal(fr)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorFreezeRecord,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertFreezeRecordFromBlobEntry(be blobEntry) (*freezeRecord, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorFreezeRecord {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorFreezeRecord)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var fr freezeRecord
	err = json.Unmarshal(b, &fr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal freezeRecord: %v", err)
	}

	return &fr, nil
}

func convertRecordIndexFromBlobEntry(be blobEntry) (*recordIndex, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
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
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var ri recordIndex
	err = json.Unmarshal(b, &ri)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordIndex: %v", err)
	}

	return &ri, nil
}

func (t *tlog) leafLatest(treeID int64) (*trillian.LogLeaf, error) {

	return nil, nil
}

func (t *tlog) freezeRecord(treeID int64) (*freezeRecord, error) {
	// Get the last leaf of the tree
	tree, err := t.client.tree(treeID)
	if err != nil {
		return nil, errRecordNotFound
	}
	_, lr, err := t.client.signedLogRoot(tree)
	if err != nil {
		return nil, fmt.Errorf("signedLogRoot: %v", err)
	}
	leaves, err := t.client.leavesByRange(treeID, int64(lr.TreeSize)-1, 1)
	if err != nil {
		return nil, fmt.Errorf("leavesByRange: %v", err)
	}
	if len(leaves) != 1 {
		return nil, fmt.Errorf("unexpected leaves count: got %v, want 1",
			len(leaves))
	}
	l := leaves[0]
	if !isFreezeRecordLeaf(l) {
		// Leaf is not a freeze record
		return nil, errFreezeRecordNotFound
	}

	// The leaf is a freeze record. Get it from the store.
	k, err := extractKeyForFreezeRecord(l)
	if err != nil {
		return nil, err
	}
	blobs, err := t.store.Get([]string{k})
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != 1 {
		return nil, fmt.Errorf("unexpected blobs count: got %v, want 1",
			len(blobs), 1)
	}

	// Decode freeze record
	b, ok := blobs[k]
	if !ok {
		return nil, fmt.Errorf("blob not found %v", k)
	}
	be, err := deblob(b)
	if err != nil {
		return nil, err
	}
	fr, err := convertFreezeRecordFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return fr, nil
}

func (t *tlog) leavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]*trillian.LogLeaf, error) {
	// TODO Ensure the tree is not frozen
	return nil, nil
}

func (t *tlog) recordIndex(leaves []*trillian.LogLeaf, version uint32) (*recordIndex, error) {
	// Walk the leaves and compile the keys of all the record indexes.
	// Appending the record index leaf to the trillian tree is the last
	// operation that occurs when updating a record, so if an index
	// leaf exists then you can be sure that the index blob exists in
	// the store as well as all of the record content blobs. It is
	// possible for multiple indexes to exist for the same record
	// version (they will have different iterations due to metadata
	// only updates) so we have to pull the index blobs from the store
	// in order to find the latest index for the specified version.
	keys := make([]string, 0, 64)
	for _, v := range leaves {
		if isRecordIndexLeaf(v) {
			// This is a record index leaf. Extract they kv store key.
			k, err := extractKeyForRecordIndex(v)
			if err != nil {
				return nil, err
			}
			keys = append(keys, k)
		}
	}

	if len(keys) == 0 {
		// No records have been added to this tree yet
		return nil, errRecordNotFound
	}

	// Get record indexes from store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	missing := make([]string, 0, len(keys))
	for _, v := range keys {
		if _, ok := blobs[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("record index not found: %v", missing)
	}

	indexes := make([]*recordIndex, 0, len(blobs))
	for _, v := range blobs {
		be, err := deblob(v)
		if err != nil {
			return nil, err
		}
		ri, err := convertRecordIndexFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		indexes = append(indexes, ri)
	}

	// Sanity check. Index iterations should start with 1 and be
	// sequential. Index versions should start with 1 and also be
	// sequential, but duplicate versions can exist as long as the
	// iteration has been incremented.
	var versionPrev uint32
	var i uint32 = 1
	for _, v := range indexes {
		if v.Iteration != i {
			return nil, fmt.Errorf("invalid record index iteration: "+
				"got %v, want %v", v.Iteration, i)
		}
		diff := v.Version - versionPrev
		if diff != 0 && diff != 1 {
			return nil, fmt.Errorf("invalid record index version: "+
				"curr version %v, prev version %v", v.Version, versionPrev)
		}

		i++
		versionPrev = v.Version
	}

	// Return the record index for the specified version. A version of
	// 0 indicates that the most recent version should be returned.
	var ri *recordIndex
	if version == 0 {
		ri = indexes[len(indexes)-1]
	} else {
		// Walk the indexes backwards so the most recent iteration of the
		// specified version is selected.
		for i := len(indexes) - 1; i >= 0; i-- {
			r := indexes[i]
			if r.Version == version {
				ri = r
				break
			}
		}
	}
	if ri == nil {
		// The specified version does not exist
		return nil, errRecordNotFound
	}

	return ri, nil
}

func (t *tlog) recordIndexLatest(leaves []*trillian.LogLeaf) (*recordIndex, error) {
	return t.recordIndex(leaves, 0)
}

func (t *tlog) recordIndexSave(treeID int64, ri recordIndex) error {
	// Save record index to the store
	be, err := convertBlobEntryFromRecordIndex(ri)
	if err != nil {
		return err
	}
	b, err := blobify(*be)
	if err != nil {
		return err
	}
	keys, err := t.store.Put([][]byte{b})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Append record index leaf to trillian tree
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	prefixedKey := []byte(keyPrefixRecordIndex + keys[0])
	queued, _, err := t.client.LeavesAppend(treeID, []*trillian.LogLeaf{
		logLeafNew(h, prefixedKey),
	})
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queud leaves: got %v, want 1",
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

type recordHashes struct {
	recordMetadata string            // Record metadata hash
	metadata       map[string]uint64 // [hash]metadataID
	files          map[string]string // [hash]filename
}

type blobsPrepareArgs struct {
	encryptionKey *EncryptionKey
	leaves        []*trillian.LogLeaf
	recordMD      backend.RecordMetadata
	metadata      []backend.MetadataStream
	files         []backend.File
}

type blobsPrepareReply struct {
	recordIndex  recordIndex
	recordHashes recordHashes

	// blobs and hashes MUST share the same ordering
	blobs  [][]byte
	hashes [][]byte
}

// TODO test this function
// TODO if we find a freeze record we need to fail
func blobsPrepare(args blobsPrepareArgs) (*blobsPrepareReply, error) {
	// Check if any of the content already exists. Different record
	// versions that reference the same data is fine, but this data
	// should not be saved to the store again. We can find duplicates
	// by walking the trillian tree and comparing the hash of the
	// provided record content to the log leaf data, which will be the
	// same for duplicates.

	// Compute record content hashes
	rhashes := recordHashes{
		metadata: make(map[string]uint64, len(args.metadata)),
		files:    make(map[string]string, len(args.files)),
	}
	b, err := json.Marshal(args.recordMD)
	if err != nil {
		return nil, err
	}
	rhashes.recordMetadata = hex.EncodeToString(util.Digest(b))
	for _, v := range args.metadata {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.metadata[h] = v.ID
	}
	for _, v := range args.files {
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
		// skipped when saving the blob to the store.
		dups = make(map[string]struct{}, 64)

		// Any duplicates that are found are added to the record index
		// since we already have the leaf data for them.
		index = recordIndex{
			Metadata: make(map[uint64][]byte, len(args.metadata)),
			Files:    make(map[string][]byte, len(args.files)),
		}
	)
	for _, v := range args.leaves {
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
	l := len(args.metadata) + len(args.files) + 1
	hashes := make([][]byte, 0, l)
	blobs := make([][]byte, 0, l)
	be, err := convertBlobEntryFromRecordMetadata(args.recordMD)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	b, err = blobify(*be)
	if err != nil {
		return nil, err
	}
	_, ok := dups[be.Hash]
	if !ok {
		// Not a duplicate. Save blob to the store.
		hashes = append(hashes, h)
		blobs = append(blobs, b)
	}

	for _, v := range args.metadata {
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Hash)
		if err != nil {
			return nil, err
		}
		b, err := blobify(*be)
		if err != nil {
			return nil, err
		}
		_, ok := dups[be.Hash]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	for _, v := range args.files {
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Hash)
		if err != nil {
			return nil, err
		}
		b, err := blobify(*be)
		if err != nil {
			return nil, err
		}
		// Encypt file blobs if encryption key has been set
		if args.encryptionKey != nil {
			b, err = args.encryptionKey.Encrypt(blobEntryVersion, b)
			if err != nil {
				return nil, err
			}
		}
		_, ok := dups[be.Hash]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	return &blobsPrepareReply{
		recordIndex:  index,
		recordHashes: rhashes,
		blobs:        blobs,
		hashes:       hashes,
	}, nil
}

func (t *tlog) blobsSave(treeID int64, bpr blobsPrepareReply) (*recordIndex, error) {
	var (
		index   = bpr.recordIndex
		rhashes = bpr.recordHashes
		blobs   = bpr.blobs
		hashes  = bpr.hashes
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
		pk := []byte(keyPrefixRecordContent + keys[k])
		leaves = append(leaves, logLeafNew(hashes[k], pk))
	}

	// Append leaves to trillian tree
	queued, _, err := t.client.LeavesAppend(treeID, leaves)
	if err != nil {
		return nil, fmt.Errorf("LeavesAppend: %v", err)
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

func (t *tlog) treeNew() (int64, error) {
	tree, _, err := t.client.treeNew()
	if err != nil {
		return 0, err
	}
	return tree.TreeId, nil
}

func (t *tlog) treeExists(treeID int64) bool {
	_, err := t.client.tree(treeID)
	if err == nil {
		return true
	}
	return false
}

func (t *tlog) recordIsFrozen(treeID int64) (bool, error) {
	tree, err := t.client.tree(treeID)
	if err != nil {
		return false, fmt.Errorf("tree: %v", err)
	}
	if tree.TreeState == trillian.TreeState_FROZEN {
		return true, nil
	}

	// Its possible that a freeze record has been added to the tree but
	// the call to flip the tree state to frozen has failed. In this
	// case the tree is still considered frozen. We need to manually
	// check the last leaf of the tree to see if it is a free record.
	_, lr, err := t.client.signedLogRoot(tree)
	if err != nil {
		return false, fmt.Errorf("signedLogRoot: %v", err)
	}
	leaves, err := t.client.leavesByRange(treeID, int64(lr.TreeSize)-1, 1)
	if err != nil {
		return false, fmt.Errorf("leavesByRange: %v", err)
	}
	if len(leaves) != 1 {
		return false, fmt.Errorf("unexpected leaves count: got %v, want 1",
			len(leaves))
	}
	if !isFreezeRecordLeaf(leaves[0]) {
		// Not a freeze record leaf. Tree is not frozen.
		return false, nil
	}

	// Tree has a freeze record but the tree state is not frozen. This
	// is bad. Fix it before returning.
	_, err = t.client.treeFreeze(treeID)
	if err != nil {
		return true, fmt.Errorf("treeFreeze: %v", err)
	}

	return true, nil
}

func (t *tlog) recordVersion(treeID int64, version uint32) (*backend.Record, error) {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return nil, errRecordNotFound
	}

	// Get tree leaves
	leaves, err := t.client.LeavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}

	// Get the record index for the specified version
	index, err := t.recordIndex(leaves, version)
	if err != nil {
		return nil, err
	}

	// Use the record index to pull the record content from the store.
	// The keys for the record content first need to be extracted from
	// their associated log leaf.

	// Compile merkle root hashes of record content
	merkles := make(map[string]struct{}, 64)
	merkles[hex.EncodeToString(index.RecordMetadata)] = struct{}{}
	for _, v := range index.Metadata {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}
	for _, v := range index.Files {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}

	// Walk the tree and extract the record content keys
	keys := make([]string, 0, len(index.Metadata)+len(index.Files)+1)
	for _, v := range leaves {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if !ok {
			// Not part of the record content
			continue
		}

		// Leaf is part of record content. Extract the kv store key.
		key, err := extractKeyForRecordContent(v)
		if err != nil {
			return nil, fmt.Errorf("extractKeyForRecordContent %x",
				v.MerkleLeafHash)
		}

		keys = append(keys, key)
	}

	// Get record content from store
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

	// Decode blobs
	entries := make([]blobEntry, 0, len(keys))
	for _, v := range blobs {
		var be *blobEntry
		if t.encryptionKey != nil && isEncrypted(v) {
			v, _, err = t.encryptionKey.Decrypt(v)
			if err != nil {
				return nil, err
			}
		}
		be, err := deblob(v)
		if err != nil {
			// Check if this is an encrypted blob that was not decrypted
			if t.encryptionKey == nil && isEncrypted(v) {
				return nil, fmt.Errorf("blob is encrypted but no encryption " +
					"key found to decrypt blob")
			}
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Decode blob entries
	var (
		recordMD *backend.RecordMetadata
		metadata = make([]backend.MetadataStream, 0, len(index.Metadata))
		files    = make([]backend.File, 0, len(index.Files))
	)
	for _, v := range entries {
		// Decode the data hint
		b, err := base64.StdEncoding.DecodeString(v.DataHint)
		if err != nil {
			return nil, fmt.Errorf("decode DataHint: %v", err)
		}
		var dd dataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return nil, fmt.Errorf("unmarshal DataHint: %v", err)
		}
		if dd.Type != dataTypeStructure {
			return nil, fmt.Errorf("invalid data type; got %v, want %v",
				dd.Type, dataTypeStructure)
		}

		// Decode the data
		b, err = base64.StdEncoding.DecodeString(v.Data)
		if err != nil {
			return nil, fmt.Errorf("decode Data: %v", err)
		}
		hash, err := hex.DecodeString(v.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode Hash: %v", err)
		}
		if !bytes.Equal(util.Digest(b), hash) {
			return nil, fmt.Errorf("data is not coherent; got %x, want %x",
				util.Digest(b), hash)
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
	case len(metadata) != len(index.Metadata):
		return nil, fmt.Errorf("invalid number of metadata; got %v, want %v",
			len(metadata), len(index.Metadata))
	case len(files) != len(index.Files):
		return nil, fmt.Errorf("invalid number of files; got %v, want %v",
			len(files), len(index.Files))
	}

	return &backend.Record{
		Version:        strconv.FormatUint(uint64(version), 10),
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

func (t *tlog) recordLatest(treeID int64) (*backend.Record, error) {
	return t.recordVersion(treeID, 0)
}

// We do not unwind.
func (t *tlog) recordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return errRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.client.LeavesAll(treeID)
	if err != nil {
		return fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}

	// Prepare kv store blobs
	args := blobsPrepareArgs{
		encryptionKey: t.encryptionKey,
		leaves:        leavesAll,
		recordMD:      rm,
		metadata:      metadata,
		files:         files,
	}
	bpr, err := blobsPrepare(args)
	if err != nil {
		return err
	}

	// Ensure file changes are being made
	if len(bpr.recordIndex.Files) == len(files) {
		return errNoFileChanges
	}

	// Save blobs
	idx, err := t.blobsSave(treeID, *bpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and use it to bump the version and
	// iteration of the new record index.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err == errRecordNotFound {
		// No record versions exist yet. This is fine. The version and
		// iteration will be incremented to 1.
	} else if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version + 1
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check. The record index should be fully populated at this
	// point.
	switch {
	case idx.Version != oldIdx.Version+1:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version+1)
	case idx.Iteration != oldIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
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

func (t *tlog) recordMetadataUpdate(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return errRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.client.LeavesAll(treeID)
	if err != nil {
		return fmt.Errorf("LeavesAll: %v", err)
	}

	// Prepare kv store blobs
	args := blobsPrepareArgs{
		encryptionKey: t.encryptionKey,
		leaves:        leavesAll,
		recordMD:      rm,
		metadata:      metadata,
	}
	bpr, err := blobsPrepare(args)
	if err != nil {
		return err
	}

	// Ensure metadata has been changed
	if len(bpr.blobs) == 0 {
		return errNoMetadataChanges
	}

	// Save the blobs
	idx, err := t.blobsSave(treeID, *bpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and add the unchanged fields to
	// the new record index. The version and files will remain the
	// same.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version
	idx.Files = oldIdx.Files

	// Increment the iteration
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check. The record index should be fully populated at this
	// point.
	switch {
	case idx.Version != oldIdx.Version:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version)
	case idx.Version != oldIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(oldIdx.Files):
		return fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(oldIdx.Files))
	}

	// Save record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

// treeFreeze freezes the trillian tree for the provided token. Once a tree
// has been frozen it is no longer able to be appended to. The last leaf in a
// frozen tree will correspond to a freeze record in the key-value store. A
// tree is frozen when the status of the corresponding record is updated to a
// status that locks the record, such as when a record is censored. The status
// change and the freeze record are appended to the tree using a single call.
//
// It's possible for this function to fail in between the append leaves call
// and the call that updates the tree status to frozen. If this happens the
// freeze record will be the last leaf on the tree but the tree state will not
// be frozen. The tree is still considered frozen and no new leaves should be
// appended to it. The tree state will be updated in the next fsck.
func (t *tlog) treeFreeze(treeID int64, fr freezeRecord) error {
	// Save freeze record to store
	be, err := convertBlobEntryFromFreezeRecord(fr)
	if err != nil {
		return err
	}
	b, err := blobify(*be)
	if err != nil {
		return err
	}
	keys, err := t.store.Put([][]byte{b})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Append freeze record leaf to trillian tree
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	prefixedKey := []byte(keyPrefixFreezeRecord + keys[0])
	queued, _, err := t.client.LeavesAppend(treeID, []*trillian.LogLeaf{
		logLeafNew(h, prefixedKey),
	})
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queud leaves: got %v, want 1",
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

	// Freeze the tree
	_, err = t.client.treeFreeze(treeID)
	if err != nil {
		return fmt.Errorf("treeFreeze: %v", err)
	}

	return nil
}

func (t *tlog) recordProof(treeID int64, version uint32) {}

func (t *tlog) fsck() {
	// Failed freeze
	// Failed censor
}

func (t *tlog) close() {
	// Close connections
	t.store.Close()
	t.client.Close()

	// Zero out encryption key
	if t.encryptionKey != nil {
		t.encryptionKey.Zero()
	}
}

func tlogNew() (*tlog, error) {
	return &tlog{}, nil
}
