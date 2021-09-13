// Copyright (c) 2020-2021 The Decred developers
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
	"fmt"

	"github.com/decred/politeia/util"
)

var (
	// ErrShutdown is returned when a action is attempted against a
	// store that is shutdown.
	ErrShutdown = errors.New("store is shutdown")
)

const (
	// DataTypeStructure describes a blob entry that contains a
	// structure.
	DataTypeStructure = "struct"
)

// DataDescriptor provides hints about a data blob. In practice we JSON encode
// this struture and stuff it into BlobEntry.DataHint.
type DataDescriptor struct {
	Type       string `json:"type"`                // Type of data
	Descriptor string `json:"descriptor"`          // Description of the data
	ExtraData  string `json:"extradata,omitempty"` // Value to be freely used
}

// BlobEntry is the structure used to store data in the key-value store.
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
	defer func() {
		err := zw.Close() // we must flush gzip buffers
		if err != nil {
			fmt.Printf("Close gzip writer err: %v\n", err)
		}
	}()
	enc := gob.NewEncoder(zw)
	err := enc.Encode(be)
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
	defer func() {
		err := zr.Close()
		if err != nil {
			fmt.Printf("Close gzip reader err: %v\n", err)
		}
	}()
	r := gob.NewDecoder(zr)
	var be BlobEntry
	err = r.Decode(&be)
	if err != nil {
		return nil, err
	}
	return &be, nil
}

// BlobKV represents a blob key-value store.
type BlobKV interface {
	// Put saves the provided key-value pairs to the store. This
	// operation is performed atomically.
	Put(blobs map[string][]byte, encrypt bool) error

	// Del deletes the provided blobs from the store. This operation
	// is performed atomically.
	Del(keys []string) error

	// Get returns blobs from the store for the provided keys. An entry
	// will not exist in the returned map if for any blobs that are not
	// found. It is the responsibility of the caller to ensure a blob
	// was returned for all provided keys.
	Get(keys []string) (map[string][]byte, error)

	// Closes closes the store connection.
	Close()
}
