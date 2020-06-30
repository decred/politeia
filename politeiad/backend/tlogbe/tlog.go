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
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

var (
	prefixRecordIndex = []byte("index:")
)

// We do not unwind.
type tlog struct {
	dataDir       string
	client        *TrillianClient
	encryptionKey *EncryptionKey
	store         store.Blob_
}

type versionIndex struct {
	RecordMetadata []byte            `json:"recordmetadata"`
	Metadata       map[uint64][]byte `json:"metadata"` // [metadataID]leafHash
	Files          map[string][]byte `json:"files"`    // [filename]leafHash
}

type recordIndex_ struct {
	Versions map[uint32]versionIndex `json:"versions"`
}

func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	// Converting between int64 and uint64 doesn't change the sign bit,
	// only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

func treeIDFromToken(token []byte) int64 {
	return int64(binary.LittleEndian.Uint64(token))
}

func tokenString(token []byte) string {
	return hex.EncodeToString(token)
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
	var ri recordIndex_
	err = json.Unmarshal(b, &ri)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordIndex: %v", err)
	}

	return &ri, nil
}

func (t *tlog) tokenNew() ([]byte, error) {
	tree, _, err := t.client.treeNew()
	if err != nil {
		return nil, fmt.Errorf("treeNew: %v", err)
	}
	return tokenFromTreeID(tree.TreeId), nil
}

func (t *tlog) recordExists() {}

func (t *tlog) recordGetVersion(token []byte, version uint64) (*backend.Record, error) {
	// Get tree leaves
	treeID := treeIDFromToken(token)
	leaves, err := t.client.LeavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("LeavesAll %v: %v", treeID, err)
	}

	// Walk the leaves backwards to find the most recent record index.
	var indexKey string
	prefix := []byte(prefixRecordIndex)
	for i := len(leaves) - 1; i >= 0; i-- {
		l := leaves[i]
		if bytes.HasPrefix(l.ExtraData, prefix) {
			// Record index found. Extract key.
			s := bytes.SplitAfter(l.ExtraData, prefix)
			if len(s) != 2 {
				return nil, fmt.Errorf("invalid leaf extra data: %x %s",
					l.MerkleLeafHash, l.ExtraData)
			}
			indexKey = string(s[1])
		}
	}
	if indexKey == "" {
		return nil, fmt.Errorf("record index not found")
	}

	// Get the record index from the store
	blobs, err := t.store.Get([]string{indexKey})
	if err != nil {
		return nil, fmt.Errorf("store Get %x: %v", err)
	}
	b, ok := blobs[indexKey]
	if !ok {
		return nil, fmt.Errorf("record index not found: %v", indexKey)
	}
	be, err := deblob(b)
	if err != nil {
		return nil, err
	}
	r, err := convertRecordIndexFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}
	if len(r.Versions) == 0 {
		return nil, fmt.Errorf("version indexes not found")
	}

	// Get the record content from the store
	metadata := make([]backend.MetadataStream, 0, len(idx.Metadata))
	files := make([]backend.File, 0, len(idx.Files))

	return nil, nil
}

func (t *tlog) recordGet(token []byte) (*backend.Record, error) {
	return nil, nil
}

func (t *tlog) recordSave(token []byte, metadata []backend.MetadataStream, files []backend.File, rm backend.RecordMetadata) (*backend.Record, error) {
	// Validate changes
	switch {
	case rm.Iteration == 1 && len(files) == 0:
		// A new record must contain files
		return nil, fmt.Errorf("no files")
	case rm.Iteration > 1:
		// Get the existing record and ensure that files changes are
		// being made.
	}

	// Save content to key-value store

	// Append content to trillian tree

	// Save record index

	return nil, nil
}

func (t *tlog) recordStatusUpdate() {}

func (t *tlog) recordMetdataUpdate() {}

func (t *tlog) recordProof() {}

func (t *tlog) recordFreeze(token []byte, pointer int64) {}

func (t *tlog) fsck() {
	// TODO soft delete trees that don't have leaves and are more than
	// a week old. This can happen if a record new call fails.
}
