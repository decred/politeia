// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package store

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"errors"

	"github.com/decred/politeia/util"
)

const (
	// Data descriptor types
	DataTypeStructure = "struct"
)

var (
	// ErrNotFound is emitted when a blob is not found.
	ErrNotFound = errors.New("not found")
)

// DataDescriptor provides hints about a data blob. In practise we JSON encode
// this struture and stuff it into BlobEntry.DataHint.
type DataDescriptor struct {
	Type       string `json:"type"`                // Type of data
	Descriptor string `json:"descriptor"`          // Description of the data
	ExtraData  string `json:"extradata,omitempty"` // Value to be freely used
}

// BlobEntry is the structure used to store data in the Blob key-value store.
// All data in the Blob key-value store will be encoded as a BlobEntry.
type BlobEntry struct {
	Digest   string `json:"digest"`   // SHA256 digest of data, hex encoded
	DataHint string `json:"datahint"` // Hint that describes data, base64 encoded
	Data     string `json:"data"`     // Data payload, base64 encoded
}

// NewBlobEntry returns a new BlobEntry.
func NewBlobEntry(dataHint, data []byte) BlobEntry {
	return BlobEntry{
		Digest:   hex.EncodeToString(util.Digest(data)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}
}

// Blobify encodes the provided BlobEntry into a gzipped byte slice.
func Blobify(be BlobEntry) ([]byte, error) {
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

// Deblob decodes the provided gzipped byte slice into a BlobEntry.
func Deblob(blob []byte) (*BlobEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	r := gob.NewDecoder(zr)
	var be BlobEntry
	err = r.Decode(&be)
	if err != nil {
		return nil, err
	}
	return &be, nil
}

// Blob represents a blob key-value store.
type Blob interface {
	// Put saves the provided blobs to the store. The keys for the
	// blobs are returned using the same odering that the blobs were
	// provided in. This operation is performed atomically.
	Put(blobs [][]byte) ([]string, error)

	// Del deletes the provided blobs from the store. This operation
	// is performed atomically.
	Del(keys []string) error

	// Get returns blobs from the store for the provided keys. An entry
	// will not exist in the returned map if for any blobs that are not
	// found. It is the responsibility of the caller to ensure a blob
	// was returned for all provided keys.
	Get(keys []string) (map[string][]byte, error)

	// Enum enumerates over all blobs in the store, invoking the
	// provided function for each blob.
	Enum(func(key string, blob []byte) error) error

	// Closes closes the blob store connection.
	Close()
}
