// Copyright (c) 2020-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package store

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"

	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

var (
	// ErrShutdown is returned when a action is attempted against a store that
	// is shutdown.
	ErrShutdown = errors.New("store is shutdown")

	// ErrDuplicateEntry is returned when a blob is attempted to be saved using
	// a key that already exists in the database. Automatic overwrites are not
	// allowed by the key-value store. When a caller receives this error, it can
	// decide if it would like to manually delete the entry and save a new one.
	ErrDuplicateEntry = errors.New("duplicate entry")
)

const (
	// DataTypeStructure describes a blob entry that contains a structure.
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
	enc := gob.NewEncoder(zw)
	err := enc.Encode(be)
	if err != nil {
		zw.Close()
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
		zr.Close()
		return nil, err
	}
	err = zr.Close()
	if err != nil {
		return nil, err
	}
	return &be, nil
}

// BlobKV represents a blob key-value store.
type BlobKV interface {
	// Put saves the provided key-value pairs to the store.
	//
	// Overwrites are not allowed by the key-value store. If the caller
	// attempts to save a blob using a key that already exists in the
	// key-value store, a ErrDuplicateEntry will be returned. It is up
	// to the caller to decide if it would like to manually delete the
	// entry and save a new one.
	//
	// This operation is performed atomically.
	Put(blobs map[string][]byte, encrypt bool) error

	// Del deletes the key-value store entries for the provided keys.
	//
	// This operation is performed atomically.
	Del(keys []string) error

	// Get returns the blob entries from the store for the provided keys.
	//
	// An entry will not exist in the returned map if for any blobs that
	// are not found. It is the responsibility of the caller to ensure a
	// blob was returned for all provided keys.
	Get(keys []string) (map[string][]byte, error)

	// Close closes the store connection.
	Close()
}
