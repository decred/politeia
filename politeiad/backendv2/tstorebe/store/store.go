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

	"github.com/decred/politeia/util"
)

const (
	// DataTypeStructure describes a blob entry that contains a
	// structure.
	DataTypeStructure = "struct"
)

var (
	// ErrShutdown is returned when a action is attempted against a
	// store that is shutdown.
	ErrShutdown = errors.New("store is shutdown")
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

// Tx represents an in-progess database transaction. All actions performed
// using a Tx are guaranteed to be atomic.
//
// A transaction must end with a call to Commit or Rollback.
type Tx interface {
	// Put saves the provided key-value pairs to the store.
	Put(blobs map[string][]byte, encrypt bool) error

	// Del deletes the provided blobs from the store.
	Del(keys []string) error

	// Get retrieves entries from the store. An entry will not exist in
	// the returned map for any blobs that are not found. It is the
	// responsibility of the caller to ensure a blob was returned for
	// all provided keys.
	Get(keys []string) (map[string][]byte, error)

	// Rollback aborts the transaction.
	Rollback() error

	// Commit commits the transaction.
	Commit() error
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

	// Tx returns a new database transaction and a cancel function
	// for the transaction.
	//
	// The cancel function is used until the tx is committed or rolled
	// backed. Invoking the cancel function rolls the tx back and
	// releases all resources associated with it. This allows the
	// caller to defer the cancel function in order to rollback the
	// tx on unexpected errors. Once the tx is successfully committed
	// the deferred invocation does nothing.
	Tx() (Tx, func(), error)

	// Closes closes the store connection.
	Close()
}

// Getter describes the get method that is present on both the BlobKV interface
// and the Tx interface. This allows us to use the same code for executing
// individual get requests and get requests that are part of a transaction.
type Getter interface {
	Get(keys []string) (map[string][]byte, error)
}
