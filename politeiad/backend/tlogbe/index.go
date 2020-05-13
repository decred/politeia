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
	stateUnvetted = "unvetted"
	stateVetted   = "vetted"
)

// recordIndex represents an index for a backend Record. The merkleLeafHash
// refers to a trillian LogLeaf.MerkleLeafHash. This value can be used to
// lookup the inclusion proof from a trillian tree as well as the actual data
// from the blob storage layer. All merkleLeafHashes are hex encoded.
type recordIndex struct {
	RecordMetadata string            `json:"recordmetadata"` // RecordMetadata merkleLeafHash
	Metadata       map[uint64]string `json:"metadata"`       // [mdstreamID]merkleLeafHash
	Files          map[string]string `json:"files"`          // [filename]merkleLeafHash
}

// recordHistory provides the record index for all versions of a record. The
// recordHistory is stored to the blob storage layer with the token as the key.
type recordHistory struct {
	Token    string                 `json:"token"`
	State    string                 `json:"state"`    // Unvetted or vetted
	Versions map[uint32]recordIndex `json:"versions"` // [version]recordIndex
}

func latestVersion(rh recordHistory) uint32 {
	return uint32(len(rh.Versions)) - 1
}

func (t *tlogbe) recordHistory(token string) (*recordHistory, error) {
	b, err := t.blob.Get(token)
	if err != nil {
		return nil, fmt.Errorf("blob get: %v", err)
	}
	var rh recordHistory
	err = json.Unmarshal(b, &rh)
	if err != nil {
		return nil, err
	}
	return &rh, nil
}

// recordHistoryAdd adds the provided recordIndex as a new version to the
// recordHistory.
func (t *tlogbe) recordHistoryAdd(token string, ri recordIndex) (*recordHistory, error) {
	// TODO implement
	// A new version can only be added to vetted records
	return nil, nil
}

// recordHistoryUpdate updates the existing version of the recordHistory with
// the provided state and recordIndex.
func (t *tlogbe) recordHistoryUpdate(token, state string, ri recordIndex) (*recordHistory, error) {
	// TODO implement
	// This will be needed for unvetted updates and metadata updates
	return nil, nil
}

func (t *tlogbe) recordIndexLatest(token string) (*recordIndex, error) {
	rh, err := t.recordHistory(token)
	if err != nil {
		return nil, err
	}
	latest := rh.Versions[latestVersion(*rh)]
	return &latest, nil
}

// recordIndexUpdate updates the provided recordIndex with the provided
// blobEntries then returns the updated recordIndex.
func recordIndexUpdate(r recordIndex, entries []blobEntry, proofs []queuedLeafProof) (*recordIndex, error) {
	// TODO implement
	return nil, nil
}

func recordIndexNew(entries []blobEntry, proofs []queuedLeafProof) (*recordIndex, error) {
	merkleHashes := make(map[string]string, len(entries)) // [leafValue]merkleLeafHash
	for _, v := range proofs {
		leafValue := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)
		merkleHash := hex.EncodeToString(v.QueuedLeaf.Leaf.MerkleLeafHash)
		merkleHashes[leafValue] = merkleHash
	}

	// Find the merkleLeafHash for each of the record components. The
	// blobEntry.Hash is the value that is saved to trillian as the
	// LogLeaf.LeafValue.
	var (
		recordMD string
		metadata = make(map[uint64]string, len(entries)) // [mdstreamID]merkleLeafHash
		files    = make(map[string]string, len(entries)) // [filename]merkleLeafHash
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
			merkleHash, ok := merkleHashes[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for record metadata")
			}
			recordMD = merkleHash
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
			merkleHash, ok := merkleHashes[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for mdstream %v", ms.ID)
			}
			metadata[ms.ID] = merkleHash
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
			merkleHash, ok := merkleHashes[v.Hash]
			if !ok {
				return nil, fmt.Errorf("merkle not found for file %v", f.Name)
			}
			files[f.Name] = merkleHash
		}
	}

	return &recordIndex{
		RecordMetadata: recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}
