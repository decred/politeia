// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/marcopeereboom/sbox"
	"github.com/robfig/cron"
	"google.golang.org/grpc/codes"
)

// TODO we need to seperate testnet and mainnet trillian trees. This will need
// to be done through setup scripts and config options. Use different ports for
// testnet.
// TODO lock on the token level

const (
	defaultTrillianKeyFilename   = "trillian.key"
	defaultEncryptionKeyFilename = "tlogbe.key"

	recordsDirname = "records"
)

var (
	_ backend.Backend = (*tlogbe)(nil)

	// statusChanges contains the allowed record status changes.
	statusChanges = map[backend.MDStatusT]map[backend.MDStatusT]struct{}{
		// Unvetted status changes
		backend.MDStatusUnvetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusIterationUnvetted: struct{}{},
			backend.MDStatusVetted:            struct{}{},
			backend.MDStatusCensored:          struct{}{},
		},
		backend.MDStatusIterationUnvetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusVetted:   struct{}{},
			backend.MDStatusCensored: struct{}{},
		},

		// Vetted status changes
		backend.MDStatusVetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusArchived: struct{}{},
		},
	}
)

// tlogbe implements the Backend interface.
type tlogbe struct {
	sync.RWMutex
	shutdown      bool
	homeDir       string
	dataDir       string
	dcrtimeHost   string
	encryptionKey *EncryptionKey
	store         store.Blob
	tlog          *TrillianClient
	cron          *cron.Cron
	plugins       []backend.Plugin

	unvetted *tlog
	vetted   *tlog

	// prefixes contains the first n characters of each record token,
	// where n is defined by the TokenPrefixLength from the politeiad
	// API. Lookups by token prefix are allowed. This cache is used to
	// prevent prefix collisions when creating new tokens.
	prefixes map[string]struct{}

	// droppingAnchor indicates whether tlogbe is in the process of
	// dropping an anchor, i.e. timestamping unanchored trillian trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool
}

// statusChangeIsAllowed returns whether the provided status change is allowed
// by tlogbe. An invalid 'from' status will panic since the 'from' status
// represents the existing status of a record and should never be invalid.
func statusChangeIsAllowed(from, to backend.MDStatusT) bool {
	allowed, ok := statusChanges[from]
	if !ok {
		e := fmt.Sprintf("status invalid: %v", from)
		panic(e)
	}
	_, ok = allowed[to]
	return ok
}

func merkleRoot(files []backend.File) (*[sha256.Size]byte, error) {
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		b, err := hex.DecodeString(v.Digest)
		if err != nil {
			return nil, err
		}
		var d [sha256.Size]byte
		copy(d[:], b)
		hashes = append(hashes, &d)
	}
	return merkle.Root(hashes), nil
}

func recordMetadataNew(token []byte, files []backend.File, status backend.MDStatusT, iteration uint64) (*backend.RecordMetadata, error) {
	m, err := merkleRoot(files)
	if err != nil {
		return nil, err
	}
	return &backend.RecordMetadata{
		Version:   backend.VersionRecordMD,
		Iteration: iteration,
		Status:    status,
		Merkle:    hex.EncodeToString(m[:]),
		Timestamp: time.Now().Unix(),
		Token:     tokenString(token),
	}, nil
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

func convertBlobEntryFromRecordHistory(rh recordHistory) (*blobEntry, error) {
	data, err := json.Marshal(rh)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorRecordHistory,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntriesFromFiles(files []backend.File) ([]blobEntry, error) {
	entries := make([]blobEntry, 0, len(files))
	for _, v := range files {
		re, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *re)
	}
	return entries, nil
}

func convertBlobEntriesFromMetadataStreams(streams []backend.MetadataStream) ([]blobEntry, error) {
	entries := make([]blobEntry, 0, len(streams))
	for _, v := range streams {
		re, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *re)
	}
	return entries, nil
}

func convertRecordMetadataFromBlobEntry(be blobEntry) (*backend.RecordMetadata, error) {
	// Decode and validate the DataHint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorRecordMetadata {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorRecordMetadata)
	}

	// Decode the MetadataStream
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	var rm backend.RecordMetadata
	err = json.Unmarshal(b, &rm)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RecordMetadata: %v", err)
	}

	return &rm, nil
}

func convertMetadataStreamFromBlobEntry(be blobEntry) (*backend.MetadataStream, error) {
	// Decode and validate the DataHint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorMetadataStream {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorMetadataStream)
	}

	// Decode the MetadataStream
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	var ms backend.MetadataStream
	err = json.Unmarshal(b, &ms)
	if err != nil {
		return nil, fmt.Errorf("unmarshal MetadataStream: %v", err)
	}

	return &ms, nil
}

func convertFileFromBlobEntry(be blobEntry) (*backend.File, error) {
	// Decode and validate the DataHint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorFile {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorFile)
	}

	// Decode the MetadataStream
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	var f backend.File
	err = json.Unmarshal(b, &f)
	if err != nil {
		return nil, fmt.Errorf("unmarshal File: %v", err)
	}

	return &f, nil
}

func convertLeavesFromBlobEntries(entries []blobEntry) ([]*trillian.LogLeaf, error) {
	leaves := make([]*trillian.LogLeaf, 0, len(entries))
	for _, v := range entries {
		b, err := hex.DecodeString(v.Hash)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, logLeafNew(b))
	}
	return leaves, nil
}

func convertRecordHistoryFromBlobEntry(be blobEntry) (*recordHistory, error) {
	// Decode and validate the DataHint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd dataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorRecordHistory {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorRecordHistory)
	}

	// Decode the MetadataStream
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	var rh recordHistory
	err = json.Unmarshal(b, &rh)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordHistory: %v", err)
	}

	return &rh, nil
}

func filesApplyChanges(files, filesAdd []backend.File, filesDel []string) []backend.File {
	del := make(map[string]struct{}, len(filesDel))
	for _, fn := range filesDel {
		del[fn] = struct{}{}
	}
	f := make([]backend.File, 0, len(files)+len(filesAdd))
	for _, v := range files {
		if _, ok := del[v.Name]; ok {
			continue
		}
		f = append(f, v)
	}
	for _, v := range filesAdd {
		f = append(f, v)
	}
	return f
}

func metadataStreamsApplyChanges(md, mdAppend, mdOverwrite []backend.MetadataStream) []backend.MetadataStream {
	// Include all overwrites
	metadata := make([]backend.MetadataStream, 0, len(md)+len(mdOverwrite))
	for _, v := range mdOverwrite {
		metadata = append(metadata, v)
	}

	// Add in existing metadata that wasn't overwritten
	overwrite := make(map[uint64]struct{}, len(mdOverwrite))
	for _, v := range mdOverwrite {
		overwrite[v.ID] = struct{}{}
	}
	for _, v := range md {
		if _, ok := overwrite[v.ID]; ok {
			// Metadata has already been overwritten
			continue
		}
		metadata = append(metadata, v)
	}

	// Apply appends
	appends := make(map[uint64]backend.MetadataStream, len(mdAppend))
	for _, v := range mdAppend {
		appends[v.ID] = v
	}
	for i, v := range metadata {
		ms, ok := appends[v.ID]
		if !ok {
			continue
		}
		buf := bytes.NewBuffer([]byte(v.Payload))
		buf.WriteString(ms.Payload)
		metadata[i].Payload = buf.String()
	}

	return metadata
}

// blobEntriesAppend appends the provided blob entries onto the trillain tree
// that corresponds to the provided token. An error is returned if any leaves
// are not successfully added. The only exception to this is if a leaf is not
// appended because it is a duplicate. This can happen in certain situations
// such as when a file is deleted from a record then added back to the record
// without being altered. The order of the returned leaf proofs is not
// guaranteed.
func (t *tlogbe) blobEntriesAppend(token []byte, entries []blobEntry) ([]LeafProof, *types.LogRootV1, error) {
	// Setup request
	treeID := treeIDFromToken(token)
	leaves, err := convertLeavesFromBlobEntries(entries)
	if err != nil {
		return nil, nil, err
	}

	// Append leaves
	queued, lr, err := t.tlog.LeavesAppend(treeID, leaves)
	if err != nil {
		return nil, nil, fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != len(leaves) {
		// Sanity check. Even if a leaf fails to be appended there should
		// still be a QueuedLogLeaf with the error code.
		return nil, nil, fmt.Errorf("wrong number of leaves: got %v, want %v",
			len(queued), len(leaves))
	}

	// Convert queuedLeafProofs to leafProofs. Fail if any of the
	// leaves were not appended successfully. The exception to this is
	// if the leaf was not appended because it was a duplicate.
	proofs := make([]LeafProof, 0, len(queued))
	dups := make([][]byte, 0, len(queued))
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		switch c {
		case codes.OK:
			// Leaf successfully appended to tree
			proofs = append(proofs, LeafProof{
				Leaf:  v.QueuedLeaf.Leaf,
				Proof: v.Proof,
			})

		case codes.AlreadyExists:
			// We need to retrieve the leaf proof manually for this leaf
			// because it was a duplicate. This can happen in certain
			// situations such as when a record file is deleted then added
			// back at a later date without being altered. A duplicate in
			// trillian is ok. A duplicate in the storage layer is not ok
			// so check the storage layer first to ensure this is not a
			// real duplicate.
			m := merkleLeafHash(v.QueuedLeaf.Leaf.LeafValue)
			_, err := t.store.Get(keyRecordContent(token, m))
			if err == nil {
				return nil, nil, fmt.Errorf("duplicate found in store: %x", m)
			}
			dups = append(dups, m)

			log.Debugf("Duplicate leaf %x, retreiving proof manually", m)

		default:
			// All other errors. This is not ok.
			failed = append(failed, fmt.Sprint("%v", c))
		}
	}
	if len(failed) > 0 {
		return nil, nil, fmt.Errorf("append leaves failed: %v", failed)
	}

	// Retrieve leaf proofs for duplicates
	if len(dups) > 0 {
		p, err := t.tlog.LeafProofs(treeID, dups, lr)
		if err != nil {
			return nil, nil, fmt.Errorf("leafProofs: %v", err)
		}
		proofs = append(proofs, p...)
	}

	return proofs, lr, nil
}

func (t *tlogbe) recordMetadata(token, merkleLeafHash []byte) (*backend.RecordMetadata, error) {
	log.Tracef("recordMetadata: %x", merkleLeafHash)

	key := keyRecordContent(token, merkleLeafHash)
	b, err := t.store.Get(key)
	if err != nil {
		return nil, err
	}
	be, err := deblob(b)
	if err != nil {
		return nil, err
	}
	rm, err := convertRecordMetadataFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return rm, nil
}

func (t *tlogbe) metadataStream(token, merkleLeafHash []byte) (*backend.MetadataStream, error) {
	log.Tracef("metadataStream: %x", merkleLeafHash)

	key := keyRecordContent(token, merkleLeafHash)
	b, err := t.store.Get(key)
	if err != nil {
		return nil, err
	}
	be, err := deblob(b)
	if err != nil {
		return nil, err
	}
	ms, err := convertMetadataStreamFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return ms, nil
}

func (t *tlogbe) file(token, merkleLeafHash []byte, state string) (*backend.File, error) {
	log.Tracef("file: %v %x", state, merkleLeafHash)

	key := keyRecordContent(token, merkleLeafHash)
	b, err := t.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	var be *blobEntry
	switch state {
	case stateUnvetted:
		// Unvetted backend File blobs will be encrypted
		be, err = deblobEncrypted(b, t.encryptionKey)
		if err != nil {
			return nil, err
		}
	case stateVetted:
		// Vetted backend File blobs will not be encrypted
		be, err = deblob(b)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown record history state: %v", state)
	}
	f, err := convertFileFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// record returns the backend record given the record index.
func (t *tlogbe) record(token []byte, ri recordIndex, version uint32, state string) (*backend.Record, error) {
	log.Tracef("record: %x", token)

	recordMD, err := t.recordMetadata(token, ri.RecordMetadata)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata %x: %v", ri.RecordMetadata, err)
	}

	metadata := make([]backend.MetadataStream, 0, len(ri.Metadata))
	for id, merkle := range ri.Metadata {
		ms, err := t.metadataStream(token, merkle)
		if err != nil {
			return nil, fmt.Errorf("metadataStream %v %x: %v", id, merkle, err)
		}
		metadata = append(metadata, *ms)
	}

	files := make([]backend.File, 0, len(ri.Files))
	for fn, merkle := range ri.Files {
		f, err := t.file(token, merkle, state)
		if err != nil {
			return nil, fmt.Errorf("file %v %x: %v", fn, merkle, err)
		}
		files = append(files, *f)
	}

	return &backend.Record{
		Version:        strconv.FormatUint(uint64(version), 10),
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

// recordSave saves the provided record as a new version. This includes
// appending the hashes of the record contents onto the associated trillian
// tree, saving the record contents as blobs in the storage layer, and saving
// a record index. This function assumes the record contents have already been
// validated.
func (t *tlogbe) recordSave(token []byte, metadata []backend.MetadataStream, files []backend.File, recordMD backend.RecordMetadata, rh recordHistory) (*backend.Record, error) {
	// Prepare blob entries
	recordMDEntry, err := convertBlobEntryFromRecordMetadata(recordMD)
	if err != nil {
		return nil, err
	}
	metadataEntries, err := convertBlobEntriesFromMetadataStreams(metadata)
	if err != nil {
		return nil, err
	}
	fileEntries, err := convertBlobEntriesFromFiles(files)
	if err != nil {
		return nil, err
	}

	// The RecordMetadata is intentionally put first so that it is
	// added to the trillian tree first. If we ever need to walk the
	// tree a RecordMetadata will signify the start of a new record.
	entries := make([]blobEntry, 0, len(metadata)+len(files)+1)
	entries = append(entries, *recordMDEntry)
	entries = append(entries, metadataEntries...)
	entries = append(entries, fileEntries...)

	// Append leaves onto trillian tree for all record contents
	proofs, _, err := t.blobEntriesAppend(token, entries)
	if err != nil {
		return nil, fmt.Errorf("blobEntriesAppend %x: %v", token, err)
	}

	// Aggregate the merkle leaf hashes. These are used as the keys
	// when saving blobs to the key-value store.
	merkles := make(map[string][]byte, len(entries)) // [leafValue]merkleLeafHash
	for _, v := range proofs {
		k := hex.EncodeToString(v.Leaf.LeafValue)
		merkles[k] = v.Leaf.MerkleLeafHash
	}

	// Aggregate the blob entry hashes of all the file blobs. These
	// are used to determine if the blob entry should be encrypted.
	// Unvetted files are stored as encrypted blobs. All other record
	// content is stored as unencrypted blobs.
	fileHashes := make(map[string]struct{}, len(fileEntries))
	for _, v := range fileEntries {
		fileHashes[v.Hash] = struct{}{}
	}

	// Prepare blobs for the storage layer. Unvetted files are stored
	// as encrypted blobs. The merkle leaf hash is used as the key in
	// the blob key-value store for all record content.
	blobs := make(map[string][]byte, len(entries)) // [key]blob
	for _, v := range entries {
		merkle, ok := merkles[v.Hash]
		if !ok {
			return nil, fmt.Errorf("no merkle leaf hash for %v", v.Hash)
		}

		var b []byte
		_, ok = fileHashes[v.Hash]
		if ok && rh.State == stateUnvetted {
			// This is an unvetted file. Store it as an encrypted blob.
			b, err = blobifyEncrypted(v, t.encryptionKey)
			if err != nil {
				return nil, err
			}
		} else {
			// All other record content is store as unencrypted blobs.
			b, err = blobify(v)
			if err != nil {
				return nil, err
			}
		}

		blobs[keyRecordContent(token, merkle)] = b
	}

	// Retrieve the record history and add a new record index version
	// to it. This updated record history will be saved with the rest
	// of the blobs. The token is used as the record history key.
	ri, err := recordIndexNew(entries, merkles)
	if err != nil {
		return nil, err
	}
	rh.Versions[latestVersion(rh)+1] = *ri
	be, err := convertBlobEntryFromRecordHistory(rh)
	if err != nil {
		return nil, err
	}
	b, err := blobify(*be)
	if err != nil {
		return nil, err
	}
	blobs[keyRecordHistory(token)] = b

	// Save all blobs
	log.Debugf("Saving %v blobs to kv store", len(blobs))

	err = t.store.Batch(store.Ops{
		Put: blobs,
	})
	if err != nil {
		return nil, fmt.Errorf("store Batch: %v", err)
	}

	// Lookup new version of the record
	log.Debugf("Record index:\n%v", rh.String())

	version := latestVersion(rh)
	r, err := t.record(token, *ri, version, rh.State)
	if err != nil {
		return nil, fmt.Errorf("record: %v", err)
	}

	return r, nil
}

// recordUpdate updates the current version of the provided record. This
// includes appending the hashes of the record contents onto the associated
// trillian tree, saving the record contents as blobs in the storage layer, and
// updating the existing record index. This function assumes the record
// contents have already been validated. The blobs for unvetted record files
// (just files, not metadata) are encrypted before being saved to the storage
// layer.
//
// This function must be called WITH the lock held.
func (t *tlogbe) recordUpdate(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string, rm backend.RecordMetadata, rh recordHistory) (*backend.Record, error) {
	log.Tracef("recordUpdate: %x", token)

	// Get the record index
	idx := rh.Versions[latestVersion(rh)]

	// entries is used to keep track of the new record content that
	// needs to be added to the trillian tree and saved to the blob
	// storage layer. The blobEntry.Hash is all that is appened onto
	// the trillian tree. The full blobEntry is saved to the blob
	// storage layer.
	l := len(mdAppend) + len(mdOverwrite) + len(filesAdd) + len(filesDel)
	entries := make([]blobEntry, 0, l)

	// encrypt tracks the blob entries that will be saved as encrypted
	// blobs.
	encrypt := make(map[string]struct{}, l) // [hash]struct{}

	// orphaned tracks the merkle leaf hashes of the blobs that have
	// been orphaned by this update. An orphaned blob is one that does
	// not correspond to a specific record version. These blobs are
	// deleted from the record index and the blob storage layer.
	orphaned := make([][]byte, 0, l)

	// Append metadata
	for _, v := range mdAppend {
		// Lookup existing metadata stream. It's ok if one does not
		// already exist. A new one will be created.
		ms := backend.MetadataStream{
			ID: v.ID,
		}
		merkle, ok := idx.Metadata[v.ID]
		if ok {
			// Metadata stream already exists. Retrieve it.
			m, err := t.metadataStream(token, merkle)
			if err != nil {
				return nil, fmt.Errorf("metadataStream %v: %v", v.ID, err)
			}
			ms.Payload = m.Payload

			// This metadata stream blob will be orphaned by the metadata
			// stream blob with the newly appended data.
			orphaned = append(orphaned, merkle)
		}

		// Append new data
		buf := bytes.NewBuffer([]byte(ms.Payload))
		buf.WriteString(v.Payload)
		ms.Payload = buf.String()
		be, err := convertBlobEntryFromMetadataStream(ms)
		if err != nil {
			return nil, err
		}

		// Save updated metadata stream
		entries = append(entries, *be)

		if ok {
			log.Debugf("Append MD %v, orphaned blob %x", v.ID, merkle)
		} else {
			log.Debugf("Append MD %v, no orphaned blob", v.ID)
		}
	}

	// Overwrite metdata
	for _, v := range mdOverwrite {
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}

		// Check if this metadata stream is a duplicate
		merkle, ok := idx.Metadata[v.ID]
		if ok {
			// Metadata stream already exists. Check if there are any
			// changes being made to it.
			b, err := hex.DecodeString(be.Hash)
			if err != nil {
				return nil, err
			}
			m := merkleLeafHash(b)
			if bytes.Equal(merkle, m) {
				// Existing metadata stream is the same as the new metadata
				// stream. No need to save it again.
				continue
			}
		}

		// Metdata stream is not a duplicate of the existing metadata
		// stream. Save it. The existing metadata stream blob will be
		// orphaned.
		entries = append(entries, *be)
		orphaned = append(orphaned, merkle)

		log.Debugf("Overwrite MD %v, orphaned blob %x", v.ID, merkle)
	}

	// Add files
	for _, v := range filesAdd {
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}

		// Check if this file is a duplicate
		merkle, ok := idx.Files[v.Name]
		if ok {
			// File name already exists. Check if there are any changes
			// being made to it.
			b, err := hex.DecodeString(be.Hash)
			if err != nil {
				return nil, err
			}
			m := merkleLeafHash(b)
			if bytes.Equal(merkle, m) {
				// Existing file is the same as the new file. No need to save
				// it again.
				continue
			}

			// New file is different. The existing file will be orphaned.
			orphaned = append(orphaned, merkle)
		}

		// Save new file
		entries = append(entries, *be)

		log.Debugf("Add file %v, orphaned blob %x", v.Name, merkle)

		// Unvetted files are stored as encryted blobs
		if rh.State == stateUnvetted {
			encrypt[be.Hash] = struct{}{}
		}
	}

	// Delete files
	for _, fn := range filesDel {
		// Ensure file exists
		merkle, ok := idx.Files[fn]
		if !ok {
			return nil, backend.ContentVerificationError{
				ErrorCode:    pd.ErrorStatusFileNotFound,
				ErrorContext: []string{fn},
			}
		}

		// This file will be orphaned
		orphaned = append(orphaned, merkle)
		log.Debugf("Del file %v, orphaned blob %x", fn, merkle)
	}

	// Check if the record metadata status is being updated
	var statusUpdate bool
	var decryptFiles bool
	currRM, err := t.recordMetadata(token, idx.RecordMetadata)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata %v: %v",
			idx.RecordMetadata, err)
	}
	if currRM.Status != rm.Status {
		// The record status is being updated
		statusUpdate = true

		log.Debugf("Record status is being updated from %v to %v",
			currRM.Status, rm.Status)

		// Check if the status is being updated from an unvetted status
		// to a vetted status. If so, we will need to decrypt the record
		// files and save them as unencrypted blobs.
		from := recordStateFromStatus[currRM.Status]
		to := recordStateFromStatus[rm.Status]
		if from == stateUnvetted && to == stateVetted {
			decryptFiles = true
		}
	}

	// Ensure changes were actually made. The only time we allow an
	// update with no changes to the files or metadata streams is when
	// the record status is being updated.
	if len(entries) == 0 && len(orphaned) == 0 && !statusUpdate {
		return nil, backend.ErrNoChanges
	}

	// Handle record metadata. The record metadata will have changed
	// if the record files are being updated or the record status is
	// being updated. It will remain unchanged if this is a metadata
	// stream only update.
	//
	// tlogbe manually updates the record status the first time that
	// an unvetted record has its files changed. The status gets
	// flipped from Unvetted to UnvettedIteration. All other status
	// changes are initiated by the client.
	filesUpdated := len(filesAdd) != 0 || len(filesDel) != 0
	if filesUpdated && rm.Status == backend.MDStatusUnvetted {
		rm.Status = backend.MDStatusIterationUnvetted
	}
	be, err := convertBlobEntryFromRecordMetadata(rm)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	m := merkleLeafHash(b)
	if !bytes.Equal(idx.RecordMetadata, m) {
		// Record metadata is not the same. Save the new one. The
		// existing record metadata is going to be orphaned.
		entries = append(entries, *be)
		orphaned = append(orphaned, idx.RecordMetadata)

		log.Debugf("Record metadata updated")
	}

	// Append leaves onto the trillian tree
	proofs, _, err := t.blobEntriesAppend(token, entries)
	if err != nil {
		return nil, fmt.Errorf("blobEntriesAppend %x: %v", token, err)
	}

	// Aggregate the merkle leaf hashes. These are used as the keys
	// when saving a blob to the key-value store.
	merkles := make(map[string][]byte, len(entries)) // [leafValue]merkleLeafHash
	for _, v := range proofs {
		k := hex.EncodeToString(v.Leaf.LeafValue)
		merkles[k] = v.Leaf.MerkleLeafHash
	}

	// Update the record index and record history
	ri, err := recordIndexUpdate(idx, entries, merkles, orphaned)
	if err != nil {
		return nil, err
	}
	rh.Versions[latestVersion(rh)] = *ri
	state, ok := recordStateFromStatus[rm.Status]
	if !ok {
		return nil, fmt.Errorf("status %v does not map to a state", rm.Status)
	}
	rh.State = state

	// Blobify all the things. The merkle leaf hash is used as the key
	// for record content in the key-value store.
	blobs := make(map[string][]byte, len(entries)+1) // [key][]byte
	for _, v := range entries {
		// Get the merkle leaf hash for this blob entry
		merkle, ok := merkles[v.Hash]
		if !ok {
			return nil, fmt.Errorf("no merkle leaf hash for %v", v.Hash)
		}

		// Sanity check. Blob should not already exist.
		_, err = t.store.Get(keyRecordContent(token, merkle))
		if err == nil {
			return nil, fmt.Errorf("unexpected blob found %v %v", v.Hash, merkle)
		}

		// Prepare blob
		var b []byte
		if _, ok := encrypt[v.Hash]; ok {
			b, err = blobifyEncrypted(v, t.encryptionKey)
		} else {
			b, err = blobify(v)
		}
		if err != nil {
			return nil, err
		}
		blobs[keyRecordContent(token, merkle)] = b
	}

	// Blobify the record history. The record token is used as the key
	// for record histories in the key-value store.
	be, err = convertBlobEntryFromRecordHistory(rh)
	if err != nil {
		return nil, err
	}
	b, err = blobify(*be)
	if err != nil {
		return nil, err
	}
	blobs[keyRecordHistory(token)] = b

	// Check if the existing file blobs in the store need to be
	// converted from encrypted blobs to unencrypted blobs.
	if decryptFiles {
		log.Debugf("Converting encrypted blobs to unecrypted blobs")
		for _, merkle := range ri.Files {
			f, err := t.file(token, merkle, stateUnvetted)
			if err != nil {
				return nil, fmt.Errorf("file %x: %v", merkle, err)
			}
			be, err := convertBlobEntryFromFile(*f)
			if err != nil {
				return nil, err
			}
			b, err := blobify(*be)
			if err != nil {
				return nil, err
			}
			blobs[keyRecordContent(token, merkle)] = b
		}
	}

	// Convert the orphaned merkle root hashes to blob keys
	del := make([]string, 0, len(orphaned))
	for _, merkle := range orphaned {
		del = append(del, keyRecordContent(token, merkle))
	}

	// Save all the blob changes
	err = t.store.Batch(store.Ops{
		Put: blobs,
		Del: del,
	})
	if err != nil {
		return nil, fmt.Errorf("store Batch: %v", err)
	}

	// Retrieve and return the updated record
	rhp, err := t.recordHistory(token)
	if err != nil {
		return nil, fmt.Errorf("recordHistory: %v", err)
	}

	log.Debugf("Record index:\n%v", rh.String())

	version := latestVersion(*rhp)
	idx = rhp.Versions[version]
	r, err := t.record(token, idx, version, rhp.State)
	if err != nil {
		return nil, fmt.Errorf("record: %v", err)
	}

	return r, nil
}

// New satisfies the Backend interface.
func (t *tlogbe) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// Validate record contents
	err := backend.VerifyContent(metadata, files, []string{})
	if err != nil {
		return nil, err
	}

	// Create token
	token, err := t.unvetted.tokenNew()
	if err != nil {
		return nil, err
	}

	// TODO handle token prefix collisions

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
	if err != nil {
		return nil, err
	}

	// Save record
	r, err := t.unvetted.recordSave(token, metadata, files, *rm)
	if err != nil {
		return nil, fmt.Errorf("unvetted save %x: %v", token, err)
	}

	log.Infof("New record %x", token)

	return &r.RecordMetadata, nil
	/*
		// Create a tree
		tree, _, err := t.client.treeNew()
		if err != nil {
			return nil, fmt.Errorf("treeNew: %v", err)
		}
		token := tokenFromTreeID(tree.TreeId)

		// Save record
		rh := recordHistoryNew(token)
		rm, err := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
		if err != nil {
			return nil, err
		}
		_, err = t.recordSave(token, metadata, files, *rm, rh)
		if err != nil {
			return nil, fmt.Errorf("recordSave %x: %v", token, err)
		}

		log.Infof("New record tree:%v token:%x", tree.TreeId, token)

		return rm, nil
	*/
}

func (t *tlogbe) UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// added. This can happen when metadata only is being updated or
		// when files are being deleted without any files being added.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
	}

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Ensure unvetted record exists
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateUnvetted {
		return nil, backend.ErrRecordNotFound
	}

	// Get existing record
	version := latestVersion(*rh)
	if version != 1 {
		// Unvetted records should only ever have a single version
		return nil, fmt.Errorf("invalid unvetted record version: %v", version)
	}
	ri := rh.Versions[version]
	r, err := t.record(token, ri, version, rh.State)
	if err != nil {
		return nil, fmt.Errorf("record %x %v: %v", token, version, err)
	}

	// Update the record metadata
	f := filesApplyChanges(r.Files, filesAdd, filesDel)
	rm, err := recordMetadataNew(token, f, r.RecordMetadata.Status,
		r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Update record
	r, err = t.recordUpdate(token, mdAppend, mdOverwrite,
		filesAdd, filesDel, *rm, *rh)
	if err != nil {
		return nil, err
	}

	// TODO Call plugin hooks

	return r, nil
}

func (t *tlogbe) UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateVettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This can happen when files are being deleted
		// without any new files being added.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
	}

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Ensure record is vetted
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateVetted {
		return nil, backend.ErrRecordNotFound
	}

	// Get existing record
	version := latestVersion(*rh)
	ri := rh.Versions[version]
	r, err := t.record(token, ri, version, rh.State)
	if err != nil {
		return nil, fmt.Errorf("record %x %v: %v", token, version, err)
	}

	// Apply changes
	files := filesApplyChanges(r.Files, filesAdd, filesDel)
	metadata := metadataStreamsApplyChanges(r.Metadata, mdAppend, mdOverwrite)

	// Ensure changes were actually made
	m1, err := merkleRoot(r.Files)
	if err != nil {
		return nil, err
	}
	m2, err := merkleRoot(files)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(m1[:], m2[:]) {
		return nil, backend.ErrNoChanges
	}

	// Create an updated record metadata
	rm, err := recordMetadataNew(token, files, r.RecordMetadata.Status,
		r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Save a new version of the record
	r, err = t.recordSave(token, metadata, files, *rm, *rh)
	if err != nil {
		return nil, fmt.Errorf("recordSave %v: %v", err)
	}

	// TODO Call plugin hooks

	return r, nil
}

func (t *tlogbe) UpdateVettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	log.Tracef("UpdateVettedMetadata: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This is expected.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return err
		}
	}

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return backend.ErrShutdown
	}

	// Ensure record is vetted
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return backend.ErrRecordNotFound
		}
		return fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateVetted {
		return backend.ErrRecordNotFound
	}

	// Get current record metadata. This will remain unchanged, but we
	// need it for the recordUpdate() call.
	version := latestVersion(*rh)
	ri := rh.Versions[version]

	rm, err := t.recordMetadata(token, ri.RecordMetadata)
	if err != nil {
		return fmt.Errorf("recordMetadata %v: %v", ri.RecordMetadata, err)
	}

	// Update record
	_, err = t.recordUpdate(token, mdAppend, mdOverwrite,
		[]backend.File{}, []string{}, *rm, *rh)
	if err != nil {
		return err
	}

	return nil
}

func (t *tlogbe) UpdateReadme(content string) error {
	return fmt.Errorf("not implemented")
}

func (t *tlogbe) UnvettedExists(token []byte) bool {
	log.Tracef("UnvettedExists %x", token)

	rh, err := t.recordHistory(token)
	if err != nil {
		if err != store.ErrNotFound {
			log.Errorf("UnvettedExists: recordHistory %x: %v", token, err)
		}
		return false
	}
	if rh.State == stateUnvetted {
		return true
	}

	return false
}

func (t *tlogbe) VettedExists(token []byte) bool {
	log.Tracef("VettedExists %x", token)

	rh, err := t.recordHistory(token)
	if err != nil {
		if err != store.ErrNotFound {
			log.Errorf("VettedExists: recordHistory %x: %v", token, err)
		}
		return false
	}
	if rh.State == stateVetted {
		return true
	}

	return false
}

func (t *tlogbe) GetUnvetted(token []byte) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x", token)

	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateUnvetted {
		return nil, backend.ErrRecordNotFound
	}
	version := latestVersion(*rh)
	ri := rh.Versions[version]

	r, err := t.record(token, ri, version, rh.State)
	if err != nil {
		return nil, fmt.Errorf("record %x %v: %v", token, version, err)
	}

	return r, nil
}

func (t *tlogbe) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x", token)

	// Ensure record is vetted
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateVetted {
		return nil, backend.ErrRecordNotFound
	}

	// Lookup record. If no version was specified, return the latest
	// version.
	var v uint32
	if version == "" {
		v = latestVersion(*rh)
	} else {
		vr, err := strconv.ParseUint(version, 10, 32)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		v = uint32(vr)
	}
	ri, ok := rh.Versions[v]
	if !ok {
		return nil, backend.ErrRecordNotFound
	}
	r, err := t.record(token, ri, uint32(v), rh.State)
	if err != nil {
		return nil, fmt.Errorf("record %x %v: %v", token, version, err)
	}

	return r, nil
}

func (t *tlogbe) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetUnvettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Ensure record is unvetted
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateUnvetted {
		return nil, backend.ErrRecordNotFound
	}

	// Get the current record metadata
	idx := rh.Versions[latestVersion(*rh)]
	rm, err := t.recordMetadata(token, idx.RecordMetadata)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata %v: %v",
			idx.RecordMetadata, err)
	}

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: rm.Status,
			To:   status,
		}
	}

	log.Debugf("Status change %x from %v (%v) to %v (%v)", token,
		backend.MDStatus[rm.Status], rm.Status, backend.MDStatus[status], status)

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Update record
	return t.recordUpdate(token, mdAppend, mdOverwrite,
		[]backend.File{}, []string{}, *rm, *rh)
}

func (t *tlogbe) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetVettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Ensure record is vetted
	rh, err := t.recordHistory(token)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordHistory %x: %v", token, err)
	}
	if rh.State != stateVetted {
		return nil, backend.ErrRecordNotFound
	}

	// Get the current record metadata
	idx := rh.Versions[latestVersion(*rh)]
	rm, err := t.recordMetadata(token, idx.RecordMetadata)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata %v: %v",
			idx.RecordMetadata, err)
	}

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: rm.Status,
			To:   status,
		}
	}

	log.Debugf("Status change %x from %v (%v) to %v (%v)", token,
		backend.MDStatus[rm.Status], rm.Status, backend.MDStatus[status], status)

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Update record
	return t.recordUpdate(token, mdAppend, mdOverwrite,
		[]backend.File{}, []string{}, *rm, *rh)
}

func (t *tlogbe) Inventory(vettedCount uint, branchCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	log.Tracef("Inventory: %v %v", includeFiles, allVersions)

	// vettedCount specifies the last N vetted records that should be
	// returned. branchCount specifies the last N branches, which in
	// gitbe correspond to unvetted records. Neither of these are
	// implemented in gitbe so they will not be implemented here
	// either. They can be added in the future if they are needed.
	switch {
	case vettedCount != 0:
		return nil, nil, fmt.Errorf("vetted count is not implemented")
	case branchCount != 0:
		return nil, nil, fmt.Errorf("branch count is not implemented")
	}

	// Get all record histories from the store
	hists := make([]recordHistory, 0, 1024)
	err := t.store.Enum(func(key string, blob []byte) error {
		if strings.HasPrefix(key, keyPrefixRecordHistory) {
			// This is a record history blob. Decode and save it.
			var rh recordHistory
			err := json.Unmarshal(blob, &rh)
			if err != nil {
				return fmt.Errorf("unmarshal recordHistory %v: %v", key, err)
			}
			hists = append(hists, rh)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("store Enum: %v", err)
	}

	// Retreive the records
	unvetted := make([]backend.Record, 0, len(hists))
	vetted := make([]backend.Record, 0, len(hists))
	for _, rh := range hists {
		for version, idx := range rh.Versions {
			if !allVersions && version != latestVersion(rh) {
				continue
			}
			r, err := t.record(rh.Token, idx, version, rh.State)
			if err != nil {
				return nil, nil, fmt.Errorf("record %v %v: %v",
					rh.Token, version, err)
			}
			if !includeFiles {
				r.Files = []backend.File{}
			}
			switch rh.State {
			case stateUnvetted:
				unvetted = append(unvetted, *r)
			case stateVetted:
				vetted = append(vetted, *r)
			default:
				return nil, nil, fmt.Errorf("unknown record history state %v: %v",
					rh.Token, rh.State)
			}
		}
	}

	return vetted, unvetted, nil
}

func (t *tlogbe) GetPlugins() ([]backend.Plugin, error) {
	log.Tracef("GetPlugins")

	// TODO implement plugins

	return t.plugins, nil
}

func (t *tlogbe) Plugin(command, payload string) (string, string, error) {
	log.Tracef("Plugin: %v", command)

	// TODO implement plugins

	return "", "", nil
}

func (t *tlogbe) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close trillian connection
	t.tlog.Close()

	// Zero out encryption key
	t.encryptionKey.Zero()
}

func New(homeDir, dataDir, trillianHost, trillianKeyFile, dcrtimeHost, encryptionKeyFile string) (*tlogbe, error) {
	// Setup encryption key file
	if encryptionKeyFile == "" {
		// No file path was given. Use the default path.
		encryptionKeyFile = filepath.Join(homeDir, defaultEncryptionKeyFilename)
	}
	if !util.FileExists(encryptionKeyFile) {
		// Encryption key file does not exist. Create one.
		log.Infof("Generating encryption key")
		key, err := sbox.NewKey()
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(encryptionKeyFile, key[:], 0400)
		if err != nil {
			return nil, err
		}
		util.Zero(key[:])
		log.Infof("Encryption key created: %v", encryptionKeyFile)
	}

	// Setup trillian client
	tlog, err := trillianClientNew(homeDir, trillianHost, trillianKeyFile)
	if err != nil {
		return nil, err
	}

	// Setup key-value store
	fp := filepath.Join(dataDir, recordsDirname)
	err = os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	// Load encryption key
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
	encryptionKey := encryptionKeyNew(&key)

	log.Infof("Encryption key loaded")

	// Setup dcrtime host
	_, err = url.Parse(dcrtimeHost)
	if err != nil {
		return nil, fmt.Errorf("parse dcrtime host '%v': %v", dcrtimeHost, err)
	}
	log.Infof("Anchor host: %v", dcrtimeHost)

	t := tlogbe{
		homeDir:       homeDir,
		dataDir:       dataDir,
		encryptionKey: encryptionKey,
		dcrtimeHost:   dcrtimeHost,
		store:         store,
		tlog:          tlog,
		cron:          cron.New(),
	}

	// Launch cron
	log.Infof("Launch cron anchor job")
	err = t.cron.AddFunc(anchorSchedule, func() {
		t.anchorTrees()
	})
	if err != nil {
		return nil, err
	}
	t.cron.Start()

	// TODO fsck

	return &t, nil
}
