// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
)

const (
	// Record states
	stateUnvetted = "unvetted"
	stateVetted   = "vetted"
)

var (
	// recordStateFromStatus maps the backend record statuses to one
	// of the record states.
	recordStateFromStatus = map[backend.MDStatusT]string{
		backend.MDStatusUnvetted:          stateUnvetted,
		backend.MDStatusIterationUnvetted: stateUnvetted,
		backend.MDStatusCensored:          stateUnvetted,
		backend.MDStatusVetted:            stateVetted,
		backend.MDStatusArchived:          stateVetted,
	}
)

// recordIndex represents an index for a backend Record that contains the
// merkle leaf hash for each piece of record content. The merkle leaf hash
// refers to the trillian LogLeaf.MerkleLeafHash that was returned when the
// record content was appened onto to the trillian tree. Each piece of record
// content is appended as a seperate leaf onto the trillian tree and thus has
// a unique merkle leaf hash. This value can be used to lookup the inclusion
// proof from the trillian tree as well as the actual content from the blob
// key-value store.
type recordIndex struct {
	RecordMetadata []byte            `json:"recordmetadata"`
	Metadata       map[uint64][]byte `json:"metadata"` // [metadataID]merkle
	Files          map[string][]byte `json:"files"`    // [filename]merkle
}

// recordHistory contains the record index for all versions of a record and
// the anchor data for all record content.
type recordHistory struct {
	Token    []byte                 `json:"token"`    // Record token
	State    string                 `json:"state"`    // Unvetted or vetted
	Versions map[uint32]recordIndex `json:"versions"` // [version]recordIndex

	// TODO remove anchor when deleting an orphaned blob
	// Anchors contains the anchored log root hash for each piece of
	// record content. It aggregates the merkle leaf hashes from all
	// record index versions. The log root hash can be used to lookup
	// the anchor structure from the key-value store, which contains
	// the dcrtime inclusion proof, or can be used to obtain the
	// inclusion proof from dcrtime itself if needed. The merkle leaf
	// hash is hex encoded. The log root hash is a SHA256 digest of the
	// encoded LogRootV1.
	Anchors map[string][]byte `json:"anchors"` // [merkleLeafHash]logRootHash
}

// String returns the recordHistory printed in human readable format.
func (r *recordHistory) String() string {
	s := fmt.Sprintf("Token: %x\n", r.Token)
	s += fmt.Sprintf("State: %v\n", r.State)
	for k, v := range r.Versions {
		s += fmt.Sprintf("Version %v\n", k)
		s += fmt.Sprintf("  RecordMD   : %x\n", v.RecordMetadata)
		for id, merkle := range v.Metadata {
			s += fmt.Sprintf("  Metadata %2v: %x\n", id, merkle)
		}
		for fn, merkle := range v.Files {
			s += fmt.Sprintf("  %-11v: %x\n", fn, merkle)
		}
	}
	return s
}

// recordIndexUpdate updates the provided recordIndex with the provided
// blobEntries and orphaned blobs then returns the updated recordIndex.
func recordIndexUpdate(idx recordIndex, entries []blobEntry, merkles map[string][]byte, orphaned [][]byte) (*recordIndex, error) {
	// Create a record index using the new blob entires
	idxNew, err := recordIndexNew(entries, merkles)
	if err != nil {
		return nil, err
	}

	// Add existing record index content to the newly created index.
	// If a merkle leaf hash is included in the orphaned list it means
	// that it is no longer part of the record and should not be
	// included. Orphaned merkle leaf hashes are put in a map for
	// linear time lookups.
	skip := make(map[string]struct{}, len(orphaned))
	for _, v := range orphaned {
		skip[hex.EncodeToString(v)] = struct{}{}
	}
	if _, ok := skip[hex.EncodeToString(idx.RecordMetadata)]; !ok {
		idxNew.RecordMetadata = idx.RecordMetadata
	}
	for k, v := range idx.Metadata {
		if _, ok := skip[hex.EncodeToString(v)]; ok {
			continue
		}
		idxNew.Metadata[k] = v
	}
	for k, v := range idx.Files {
		if _, ok := skip[hex.EncodeToString(v)]; ok {
			continue
		}
		idxNew.Files[k] = v
	}

	return idxNew, nil
}

func recordIndexNew(entries []blobEntry, merkles map[string][]byte) (*recordIndex, error) {
	// The merkle leaf hash is used to lookup a blob entry in both the
	// trillian tree and the blob key-value store. Create a record
	// index by associating each piece of record content with its
	// merkle root hash.
	var (
		recordMD []byte
		metadata = make(map[uint64][]byte, len(entries)) // [mdstreamID]merkleLeafHash
		files    = make(map[string][]byte, len(entries)) // [filename]merkleLeafHash
	)
	for _, v := range entries {
		b, err := base64.StdEncoding.DecodeString(v.DataHint)
		if err != nil {
			return nil, err
		}
		var dd dataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return nil, err
		}
		switch dd.Descriptor {
		case dataDescriptorRecordMetadata:
			merkle, ok := merkles[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for record metadata")
			}
			recordMD = merkle
			log.Debugf("Record metadata: %x", merkle)
		case dataDescriptorMetadataStream:
			b, err := base64.StdEncoding.DecodeString(v.Data)
			if err != nil {
				return nil, err
			}
			var ms backend.MetadataStream
			err = json.Unmarshal(b, &ms)
			if err != nil {
				return nil, err
			}
			merkle, ok := merkles[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for mdstream %v", ms.ID)
			}
			metadata[ms.ID] = merkle
			log.Debugf("Metadata %v: %x", ms.ID, merkle)
		case dataDescriptorFile:
			b, err := base64.StdEncoding.DecodeString(v.Data)
			if err != nil {
				return nil, err
			}
			var f backend.File
			err = json.Unmarshal(b, &f)
			if err != nil {
				return nil, err
			}
			merkle, ok := merkles[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for file %v", f.Name)
			}
			files[f.Name] = merkle
			log.Debugf("%v: %x", f.Name, merkle)
		}
	}

	return &recordIndex{
		RecordMetadata: recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

// latestVersion returns the most recent version that exists. The versions
// start at 1 so the latest version is the same as the length.
func latestVersion(rh recordHistory) uint32 {
	return uint32(len(rh.Versions))
}

func (t *tlogbe) recordHistory(token []byte) (*recordHistory, error) {
	b, err := t.store.Get(keyRecordHistory(token))
	if err != nil {
		return nil, err
	}
	be, err := deblob(b)
	if err != nil {
		return nil, err
	}
	return convertRecordHistoryFromBlobEntry(*be)
}

func recordHistoryNew(token []byte) recordHistory {
	return recordHistory{
		Token:    token,
		State:    stateUnvetted,
		Versions: make(map[uint32]recordIndex),
	}
}
