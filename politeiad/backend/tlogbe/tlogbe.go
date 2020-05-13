// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/blob"
	"github.com/decred/politeia/politeiad/backend/tlogbe/blob/filesystem"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	blobsDirname = "blobs"
)

var (
	_ backend.Backend = (*tlogbe)(nil)
)

// tlogbe implements the Backend interface.
type tlogbe struct {
	sync.RWMutex
	shutdown      bool
	root          string           // Root directory
	dcrtimeHost   string           // Dcrtimed host
	encryptionKey *[32]byte        // Private key for encrypting data
	exit          chan struct{}    // Close channel
	blob          blob.Blob        // Blob key-value store
	plugins       []backend.Plugin // Plugins

	// Trillian setup
	client     trillian.TrillianLogClient   // Trillian log client
	admin      trillian.TrillianAdminClient // Trillian admin client
	ctx        context.Context              // Context used for trillian calls
	privateKey *keyspb.PrivateKey           // Trillian signing key
	publicKey  crypto.PublicKey             // Trillian public key

	// dirty keeps track of which tree is dirty at what height. Dirty
	// means that the tree has leaves that have not been timestamped,
	// i.e. anchored, onto the decred blockchain. At start-of-day we
	// scan all records and look for STH that have not been anchored.
	// Note that we only anchor the latest STH and we do so
	// opportunistically. If the application is closed and restarted
	// it simply will drop a new anchor at the next interval; it will
	// not try to finish a prior outstanding anchor drop.
	dirty          map[int64]int64 // [treeid]height
	droppingAnchor bool            // anchor dropping is in progress
}

func tokenFromTreeID(treeID int64) string {
	b := make([]byte, binary.MaxVarintLen64)
	// Converting between int64 and uint64 doesn't change the sign bit,
	// only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return hex.EncodeToString(b)
}

func treeIDFromToken(token string) (int64, error) {
	b, err := hex.DecodeString(token)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil
}

func merkleRoot(files []backend.File) [sha256.Size]byte {
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		var d [sha256.Size]byte
		copy(d[:], v.Digest)
		hashes = append(hashes, &d)
	}
	return *merkle.Root(hashes)
}

func recordMetadataNew(token string, files []backend.File, status backend.MDStatusT, iteration uint64) backend.RecordMetadata {
	m := merkleRoot(files)
	return backend.RecordMetadata{
		Version:   backend.VersionRecordMD,
		Iteration: iteration,
		Status:    status,
		Merkle:    hex.EncodeToString(m[:]),
		Timestamp: time.Now().Unix(),
		Token:     token,
	}
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

func convertBlobEntries(mdstreams []backend.MetadataStream, files []backend.File, recordMD backend.RecordMetadata) ([]blobEntry, error) {
	blobStreams, err := convertBlobEntriesFromMetadataStreams(mdstreams)
	if err != nil {
		return nil, err
	}
	blobFiles, err := convertBlobEntriesFromFiles(files)
	if err != nil {
		return nil, err
	}
	blobRecordMD, err := convertBlobEntryFromRecordMetadata(recordMD)
	if err != nil {
		return nil, err
	}

	// The recordMD is intentionally put first. In the event that the
	// record indexes ever have to be recovered by walking the trillian
	// trees then a recordMD will mark the start of a new version of
	// the record. This should never be required, but just in case.
	entries := make([]blobEntry, 0, len(blobStreams)+len(blobFiles)+1)
	entries = append(entries, *blobRecordMD)
	entries = append(entries, blobStreams...)
	entries = append(entries, blobFiles...)

	return entries, nil
}

// blobEntriesAppend appends the provided blob entries onto the trillain tree
// that corresponds to the provided token. An error is returned if any leaves
// are not successfully added. The only exception to this is if a leaf is not
// added because it is a duplicate.
func (t *tlogbe) blobEntriesAppend(token string, entries []blobEntry) ([]queuedLeafProof, *trillian.SignedLogRoot, error) {
	// Setup request
	treeID, err := treeIDFromToken(token)
	if err != nil {
		return nil, nil, err
	}
	leaves, err := convertLeavesFromBlobEntries(entries)
	if err != nil {
		return nil, nil, err
	}

	// Append leaves
	proofs, slr, err := t.leavesAppend(treeID, leaves)
	if err != nil {
		return nil, nil, fmt.Errorf("leavesAppend: %v", err)
	}
	if len(proofs) != len(leaves) {
		// Sanity check. Even if a leaf fails to be added there should
		// still be a QueuedLogLeaf with the error code.
		return nil, nil, fmt.Errorf("proofs do not match leaves: got %v, want %v",
			len(proofs), len(leaves))
	}
	missing := make([]string, 0, len(proofs))
	for _, v := range proofs {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		// Its ok if the error is because of a duplicate since it still
		// allows us to retreive an inclusion proof.
		if c != codes.OK && c != codes.AlreadyExists {
			missing = append(missing, fmt.Sprint("%v", c))
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("leaves failed with error codes %v", missing)
	}

	return proofs, slr, nil
}

func (t *tlogbe) recordMetadata(key, state string) (*backend.RecordMetadata, error) {
	b, err := t.blob.Get(key)
	if err != nil {
		return nil, fmt.Errorf("blob Get: %v", err)
	}
	var be *blobEntry
	switch state {
	case stateUnvetted:
		// Unvetted blobs will be encrypted
		be, err = deblobEncrypted(b, t.encryptionKey)
		if err != nil {
			return nil, err
		}
	case stateVetted:
		// Vetted blobs will not be encrypted
		be, err = deblob(b)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown record history state: %v", state)
	}
	rm, err := convertRecordMetadataFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}
	return rm, nil
}

func (t *tlogbe) metadataStream(key, state string) (*backend.MetadataStream, error) {
	b, err := t.blob.Get(key)
	if err != nil {
		return nil, fmt.Errorf("blob Get: %v", err)
	}
	var be *blobEntry
	switch state {
	case stateUnvetted:
		// Unvetted blobs will be encrypted
		be, err = deblobEncrypted(b, t.encryptionKey)
		if err != nil {
			return nil, err
		}
	case stateVetted:
		// Vetted blobs will not be encrypted
		be, err = deblob(b)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown record history state: %v", state)
	}
	ms, err := convertMetadataStreamFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}
	return ms, nil
}

func (t *tlogbe) file(key, state string) (*backend.File, error) {
	b, err := t.blob.Get(key)
	if err != nil {
		return nil, fmt.Errorf("blob Get: %v", err)
	}
	var be *blobEntry
	switch state {
	case stateUnvetted:
		// Unvetted blobs will be encrypted
		be, err = deblobEncrypted(b, t.encryptionKey)
		if err != nil {
			return nil, err
		}
	case stateVetted:
		// Vetted blobs will not be encrypted
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
func (t *tlogbe) record(ri recordIndex, version uint32, state string) (*backend.Record, error) {
	recordMD, err := t.recordMetadata(ri.RecordMetadata, state)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata: %v", err)
	}
	metadata := make([]backend.MetadataStream, 0, len(ri.Metadata))
	for _, v := range ri.Metadata {
		ms, err := t.metadataStream(v, state)
		if err != nil {
			return nil, fmt.Errorf("metadataStream %v: %v", v, err)
		}
		metadata = append(metadata, *ms)
	}
	files := make([]backend.File, 0, len(ri.Files))
	for _, v := range ri.Files {
		f, err := t.file(v, state)
		if err != nil {
			return nil, fmt.Errorf("file %v: %v", v, err)
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
// validated. The blobs for unvetted record files (just files, not metadata)
// are encrypted before being saved to the storage layer.
func (t *tlogbe) recordSave(token string, metadata []backend.MetadataStream, files []backend.File, recordMD backend.RecordMetadata) error {
	// TODO implement this and remove the recordSaveUnvetted and
	// recordSaveVetted functions.
	return nil
}

// recordUpdate updates the current version of the provided record. This
// includes appending the hashes of the record contents onto the associated
// trillian tree, saving the record contents as blobs in the storage layer, and
// updating the existing record index. This function assumes the record
// contents have already been validated. The blobs for unvetted record files
// (just files, not metadata) are encrypted before being saved to the storage
// layer.
//
// It is the responsibility of the caller to remove any blobs that were
// orphaned by this update from the storage layer.
func (t *tlogbe) recordUpdate(token string, metadata []backend.MetadataStream, files []backend.File,
	recordMD backend.RecordMetadata) error {
	// TODO implement this and remove the recordSaveUnvetted and
	// recordSaveVetted functions.
	return nil
}

// recordSaveUnvetted saves the hashes of the record contents to the provided
// trillian tree, saves the record contents as blobs in the storage layer, and
// saves an index of the record that can be used to lookup both the trillian
// inclusion proofs and the blobs required to reconstruct the record. This
// function assumes the record contents have already been validated. Unvetted
// record blobs are encrypted before being saved to the storage layer.
func (t *tlogbe) recordSaveUnvetted(token string, mdstreams []backend.MetadataStream, files []backend.File, recordMD backend.RecordMetadata) error {
	// Prepare blob entries
	entries, err := convertBlobEntries(mdstreams, files, recordMD)
	if err != nil {
		return err
	}

	// Append leaves onto trillian tree for all record contents
	proofs, _, err := t.blobEntriesAppend(token, entries)
	if err != nil {
		return err
	}

	// The merkleLeafHash is used as the key for the blob in the
	// storage layer.
	merkleHashes := make(map[string]string, len(entries)) // [leafValue]merkleLeafHash
	for _, v := range proofs {
		leafValue := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)
		merkleHash := hex.EncodeToString(v.QueuedLeaf.Leaf.MerkleLeafHash)
		merkleHashes[leafValue] = merkleHash
	}

	// Prepare blobs for the storage layer. Unvetted record blobs are
	// encrypted.
	blobs := make(map[string][]byte, len(entries)) // [merkleLeafHash]blob
	for _, v := range entries {
		// Get the merkle leaf hash that corresponds to this blob entry
		merkle, ok := merkleHashes[v.Hash]
		if !ok {
			return fmt.Errorf("no merkle leaf hash found for %v", v.Hash)
		}

		// Check if this blob already exists in the storage layer. This
		// can happen when a new record version is submitted but some of
		// the the files and mdstreams remains the same.
		_, err = t.blob.Get(merkle)
		if err == nil {
			// Blob aleady exists. Skip it.
			continue
		}

		// Prepare encrypted blob
		b, err := blobifyEncrypted(v, t.encryptionKey)
		if err != nil {
			return err
		}
		blobs[merkle] = b
	}

	// Update the record history and blobify it
	ri, err := recordIndexNew(entries, proofs)
	if err != nil {
		return err
	}
	rh, err := t.recordHistoryUpdate(token, stateUnvetted, *ri)
	if err != nil {
		return err
	}
	be, err := convertBlobEntryFromRecordHistory(*rh)
	if err != nil {
		return err
	}
	b, err := blobify(*be)
	if err != nil {
		return err
	}
	blobs[token] = b

	// Save all blobs
	err = t.blob.PutMulti(blobs)
	if err != nil {
		return fmt.Errorf("blob PutMulti: %v", err)
	}

	return nil
}

// recordSaveVetted saves the hashes of the record contents to the provided
// trillian tree, saves the record contents as blobs in the storage layer, and
// saves a record index that can be used to lookup both the trillian inclusion
// proofs and the blobs required to reconstruct the record. This function
// assumes the record contents have already been validated. Vetted record blobs
// are NOT encrypted before being saved to the storage layer.
func (t *tlogbe) recordSaveVetted(token string, version uint32, mdstreams []backend.MetadataStream, files []backend.File, recordMD backend.RecordMetadata) error {
	// Prepare blob entries
	entries, err := convertBlobEntries(mdstreams, files, recordMD)
	if err != nil {
		return err
	}

	// Append leaves onto trillian tree for all record contents
	proofs, _, err := t.blobEntriesAppend(token, entries)
	if err != nil {
		return err
	}

	// The merkleLeafHash is used as the key for the blob in the
	// storage layer.
	merkleHashes := make(map[string]string, len(entries)) // [leafValue]merkleLeafHash
	for _, v := range proofs {
		leafValue := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)
		merkleHash := hex.EncodeToString(v.QueuedLeaf.Leaf.MerkleLeafHash)
		merkleHashes[leafValue] = merkleHash
	}

	// Prepare blobs for the storage layer. Vetted record blobs are not
	// encrypted.
	blobs := make(map[string][]byte, len(entries)) // [merkleLeafHash]blob
	for _, v := range entries {
		// Get the merkle leaf hash that corresponds to this blob entry
		merkle, ok := merkleHashes[v.Hash]
		if !ok {
			return fmt.Errorf("no merkle leaf hash found for %v", v.Hash)
		}

		// Check if this blob already exists in the storage layer. This
		// can happen when a new record version is submitted but some of
		// the the files and mdstreams remains the same.
		_, err = t.blob.Get(merkle)
		if err == nil {
			// Blob aleady exists. Skip it.
			continue
		}

		// Prepare blob
		b, err := blobify(v)
		if err != nil {
			return err
		}
		blobs[merkle] = b
	}

	// Add a record index to the record history and blobify it
	ri, err := recordIndexNew(entries, proofs)
	if err != nil {
		return err
	}
	rh, err := t.recordHistoryAdd(token, *ri)
	if err != nil {
		return err
	}
	be, err := convertBlobEntryFromRecordHistory(*rh)
	if err != nil {
		return err
	}
	b, err := blobify(*be)
	if err != nil {
		return err
	}
	blobs[token] = b

	// Save all blobs
	err = t.blob.PutMulti(blobs)
	if err != nil {
		return fmt.Errorf("blob PutMulti: %v", err)
	}

	return nil
}

// New satisfies the Backend interface.
func (t *tlogbe) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// Validate record contents
	err := backend.VerifyContent(metadata, files, []string{})
	if err != nil {
		return nil, err
	}

	// Create a new trillian tree. The treeID is used as the record
	// token.
	// TODO handle token prefix collisions
	tree, _, err := t.treeNew()
	if err != nil {
		return nil, fmt.Errorf("treeNew: %v", err)
	}
	token := tokenFromTreeID(tree.TreeId)

	// Save record
	rm := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
	err = t.recordSaveUnvetted(token, metadata, files, rm)
	if err != nil {
		return nil, fmt.Errorf("recordSaveUnvetted %v: %v", token, err)
	}

	log.Infof("New record %v %v", tree.TreeId, token)

	return &rm, nil
}

func (t *tlogbe) UpdateUnvettedRecord(tokenb []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", tokenb)

	// Send in a single metadata array to verify there are no dups
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are
		// being added. This can happen when metadata only is being
		// updated.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
	}

	token := hex.EncodeToString(tokenb)

	t.Lock()
	defer t.Unlock()

	// Ensure record is not vetted
	rh, err := t.recordHistory(token)
	if err != nil {
		return nil, fmt.Errorf("recordHistory: %v", err)
	}
	if rh.State != stateUnvetted {
		// This error doesn't really make sense in the context of tlogbe,
		// but its what the gitbe returns in this situation so we return
		// it to keep it consistent. For gitbe, it means a record was
		// found in a directory that should only contain vetted records.
		return nil, backend.ErrRecordFound
	}

	l := len(mdAppend) + len(mdOverwrite) + len(filesAdd)
	entries := make([]blobEntry, 0, l)

	// Retrive existing record index
	version := latestVersion(*rh)
	idx := rh.Versions[version]

	// Overwrite metadata. The recordIndex uses the metadata ID as the
	// key so any existing metadata will get overwritten when the new
	// recordIndex is created.
	for _, v := range mdOverwrite {
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Append metadata
	for _, v := range mdAppend {
		m, ok := idx.Metadata[v.ID]
		if !ok {
			return nil, fmt.Errorf("append metadata not found: %v", v.ID)
		}
		ms, err := t.metadataStream(m, rh.State)
		if err != nil {
			return nil, fmt.Errorf("metadataStream %v: %v", m, err)
		}
		buf := bytes.NewBuffer([]byte(ms.Payload))
		buf.WriteString(v.Payload)
		ms.Payload = buf.String()
		be, err := convertBlobEntryFromMetadataStream(*ms)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Add files
	for _, v := range filesAdd {
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Delete files
	for _, fn := range filesDel {
		_, ok := idx.Files[fn]
		if !ok {
			return nil, fmt.Errorf("file to delete not found: %v", fn)
		}
		delete(idx.Files, fn)
	}

	// TODO Ensure changes were actually made

	// Aggregate all files. We need this for the merkle root calc.
	files := make([]backend.File, 0, len(idx.Files)+len(filesAdd))
	for _, v := range idx.Files {
		f, err := t.file(v, rh.State)
		if err != nil {
			return nil, fmt.Errorf("file %v: %v", v, err)
		}
		files = append(files, *f)
	}
	for _, v := range filesAdd {
		files = append(files, v)
	}

	// Update the record metadata
	rm, err := t.recordMetadata(idx.RecordMetadata, rh.State)
	if err != nil {
		return nil, fmt.Errorf("recordMetadata %v: %v",
			idx.RecordMetadata, err)
	}
	rmNew := recordMetadataNew(token, files, rm.Status, rm.Iteration+1)
	be, err := convertBlobEntryFromRecordMetadata(rmNew)
	if err != nil {
		return nil, err
	}
	entries = append(entries, *be)

	// Append new content to the trillian tree
	proofs, _, err := t.blobEntriesAppend(token, entries)
	if err != nil {
		return nil, err
	}

	// Update the record history
	idxp, err := recordIndexUpdate(idx, entries, proofs)
	if err != nil {
		return nil, err
	}
	rh, err = t.recordHistoryUpdate(token, rh.State, *idxp)
	if err != nil {
		return nil, err
	}

	// Save blobs

	// TODO Delete orphaned blobs

	// TODO call plugin hooks

	return nil, nil
}

func (t *tlogbe) UpdateVettedRecord(tokenb []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateVettedRecord: %x", tokenb)

	return nil, nil
}

func (t *tlogbe) UpdateVettedMetadata(tokenb []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	log.Tracef("UpdateVettedMetadata: %x", tokenb)

	return nil
}

func (t *tlogbe) UpdateReadme(content string) error {
	return fmt.Errorf("not implemented")
}

func (t *tlogbe) UnvettedExists(tokenb []byte) bool {
	log.Tracef("UnvettedExists %x", tokenb)

	return false
}

func (t *tlogbe) VettedExists(tokenb []byte) bool {
	log.Tracef("VettedExists %x", tokenb)

	return false
}

func (t *tlogbe) GetUnvetted(tokenb []byte) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x", tokenb)

	return nil, nil
}

func (t *tlogbe) GetVetted(tokenb []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x", tokenb)

	return nil, nil
}

func (t *tlogbe) SetUnvettedStatus(tokenb []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetUnvettedStatus: %x", tokenb)

	return nil, nil
}

func (t *tlogbe) SetVettedStatus(tokenb []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetVettedStatus: %x", tokenb)

	return nil, nil
}

func (t *tlogbe) Inventory(vettedCount uint, branchCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	return nil, nil, nil
}

func (t *tlogbe) GetPlugins() ([]backend.Plugin, error) {
	log.Tracef("GetPlugins")

	return t.plugins, nil
}

func (t *tlogbe) Plugin(command, payload string) (string, string, error) {
	log.Tracef("Plugin: %v", command)

	return "", "", nil
}

func (t *tlogbe) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	t.shutdown = true
	close(t.exit)

	// Zero out encryption key
	util.Zero(t.encryptionKey[:])
	t.encryptionKey = nil
}

func tlogbeNew(root, trillianHost, privateKeyFile string) (*tlogbe, error) {
	// Create a new  signing key
	if !util.FileExists(privateKeyFile) {
		log.Infof("Generating signing key...")
		privateKey, err := keys.NewFromSpec(&keyspb.Specification{
			// TODO Params: &keyspb.Specification_Ed25519Params{},
			Params: &keyspb.Specification_EcdsaParams{},
		})
		if err != nil {
			return nil, err
		}
		b, err := der.MarshalPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(privateKeyFile, b, 0400)
		if err != nil {
			return nil, err
		}

		log.Infof("Signing Key created...")
	}

	// Load signing key
	var err error
	var privateKey = &keyspb.PrivateKey{}
	privateKey.Der, err = ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := der.UnmarshalPrivateKey(privateKey.Der)
	if err != nil {
		return nil, err
	}

	// Connect to trillian
	log.Infof("Trillian log server: %v", trillianHost)
	g, err := grpc.Dial(trillianHost, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer g.Close()

	// Setup blob directory
	blobsPath := filepath.Join(root, blobsDirname)
	err = os.MkdirAll(blobsPath, 0700)
	if err != nil {
		return nil, err
	}

	// TODO setup encryption key

	// TODO we need a fsck that ensures there are no orphaned blobs in
	// the storage layer and that record indexes don't have any missing
	// blobs.

	return &tlogbe{
		root:       root,
		blob:       filesystem.BlobFilesystemNew(blobsPath),
		client:     trillian.NewTrillianLogClient(g),
		admin:      trillian.NewTrillianAdminClient(g),
		ctx:        context.Background(),
		privateKey: privateKey,
		publicKey:  signer.Public(),
	}, nil
}
