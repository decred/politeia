// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"

	"github.com/decred/politeia/util"
)

const (
	blobEntryVersion uint32 = 1

	// Data descriptor types. These may be freely edited since they are
	// solely hints to the application.
	dataTypeStructure = "struct" // Descriptor contains a structure

	// Data descriptors
	dataDescriptorFile           = "file"
	dataDescriptorRecordMetadata = "recordmetadata"
	dataDescriptorMetadataStream = "metadatastream"
	dataDescriptorRecordHistory  = "recordhistory"
	dataDescriptorAnchor         = "anchor"

	dataDescriptorRecordIndex = "recordindex"

	// Key prefixes for blob entries saved to the key-value store
	keyPrefixRecordHistory = "index"
	keyPrefixRecordContent = "record"
	keyPrefixAnchor        = "anchor"
)

// dataDescriptor provides hints about a data blob. In practise we JSON encode
// this struture and stuff it into blobEntry.DataHint.
type dataDescriptor struct {
	Type       string `json:"type"`                // Type of data
	Descriptor string `json:"descriptor"`          // Description of the data
	ExtraData  string `json:"extradata,omitempty"` // Value to be freely used
}

// blobEntry is the structure used to store data in the Blob key-value store.
// All data in the Blob key-value store will be encoded as a blobEntry.
type blobEntry struct {
	Hash     string `json:"hash"`     // SHA256 hash of data payload, hex encoded
	DataHint string `json:"datahint"` // Hint that describes data, base64 encoded
	Data     string `json:"data"`     // Data payload, base64 encoded
}

// keyRecordHistory returns the key for the blob key-value store for a record
// history.
func keyRecordHistory(token []byte) string {
	return keyPrefixRecordHistory + hex.EncodeToString(token)
}

// keyRecordContent returns the key-value store key for any type of record
// content (files, metadata streams, record metadata). Its possible for two
// different records to submit the same file resulting in identical merkle leaf
// hashes. The token is included in the key to ensure that a situation like
// this does not lead to unwanted behavior.
func keyRecordContent(token, merkleLeafHash []byte) string {
	return keyPrefixRecordContent + hex.EncodeToString(token) +
		hex.EncodeToString(merkleLeafHash)
}

// keyAnchor returns the key for the blob key-value store for a anchor record.
func keyAnchor(logRootHash []byte) string {
	return keyPrefixAnchor + hex.EncodeToString(logRootHash)
}

func blobify(be blobEntry) ([]byte, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	enc := gob.NewEncoder(zw)
	err := enc.Encode(be)
	if err != nil {
		return nil, err
	}
	err = zw.Close() // we must flush gzip buffers
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func deblob(blob []byte) (*blobEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	r := gob.NewDecoder(zr)
	var be blobEntry
	err = r.Decode(&be)
	if err != nil {
		return nil, err
	}
	return &be, nil
}

func blobifyEncrypted(be blobEntry, key *EncryptionKey) ([]byte, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	enc := gob.NewEncoder(zw)
	err := enc.Encode(be)
	if err != nil {
		return nil, err
	}
	err = zw.Close() // we must flush gzip buffers
	if err != nil {
		return nil, err
	}
	blob, err := key.Encrypt(blobEntryVersion, b.Bytes())
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func deblobEncrypted(blob []byte, key *EncryptionKey) (*blobEntry, error) {
	b, _, err := key.Decrypt(blob)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	r := gob.NewDecoder(zr)
	var be blobEntry
	err = r.Decode(&be)
	if err != nil {
		return nil, err
	}
	return &be, nil
}

func blobEntryNew(dataHint, data []byte) blobEntry {
	return blobEntry{
		Hash:     hex.EncodeToString(util.Digest(data)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}
}
