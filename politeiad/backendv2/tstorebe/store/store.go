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
	"encoding/json"

	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// TODO switch GetBatch single key calls in code to Get calls

var (
	// ErrShutdown is returned when a action is attempted against a
	// store that is shutdown.
	ErrShutdown = errors.New("store is shutdown")

	// ErrNotFound is returned by some methods when the provided key
	// does not correspond to a blob entry.
	ErrNotFound = errors.New("not found")

	// ErrDuplicateKey is returned when attempting to insert a key that
	// already exists.
	ErrDuplicateKey = errors.New("duplicate key")
)

// BlobKV represents a blob key-value store.
type BlobKV interface {
	// Insert inserts a new entry into the key-value store for each
	// of the provided key-value pairs. This operation is atomic.
	//
	// An ErrDuplicateKey is returned if a provided key already exists
	// in the key-value store.
	Insert(blobs map[string][]byte, encrypt bool) error

	// Update updates the provided key-value pairs in the store. This
	// operation is atomic.
	//
	// An ErrNotFound is returned if the caller attempts to update an
	// entry that does not exist.
	Update(blobs map[string][]byte, encrypt bool) error

	// Del deletes the provided blobs from the store. This operation
	// is atomic.
	//
	// Keys that do not correspond to blob entries are ignored. An
	// error IS NOT returned.
	Del(keys []string) error

	// Get returns the blob for the provided key.
	//
	// An ErrNotFound error is returned if the key does not correspond
	// to an entry.
	Get(key string) ([]byte, error)

	// GetBatch returns the blobs for the provided keys.
	//
	// An entry will not exist in the returned map if for any blobs
	// that are not found. It is the responsibility of the caller to
	// ensure a blob was returned for all provided keys. An error is
	// not returned.
	GetBatch(keys []string) (map[string][]byte, error)

	// Tx returns a new database transaction and a cancel function
	// for the transaction.
	//
	// The cancel function is used until the tx is committed or rolled
	// backed. Invoking the cancel function rolls the tx back and
	// releases all resources associated with it. This allows the
	// caller to defer the cancel function in order to rollback the
	// tx on unexpected errors. Once the tx is successfully committed
	// the deferred invocation of the cancel function does nothing.
	Tx() (Tx, func(), error)

	// Close closes the db connection.
	Close()
}

// Tx represents an in-progess database transaction. All actions performed
// using a Tx are guaranteed to be atomic.
//
// A transaction must end with a call to Commit or Rollback.
type Tx interface {
	// Insert inserts a new entry into the key-value store for each
	// of the provided key-value pairs.
	//
	// An ErrDuplicateKey is returned if a provided key already exists
	// in the key-value store.
	Insert(blobs map[string][]byte, encrypt bool) error

	// Update updates the provided key-value pairs in the store.
	//
	// An ErrNotFound is returned if the caller attempts to update an
	// entry that does not exist.
	Update(blobs map[string][]byte, encrypt bool) error

	// Del deletes the provided blobs from the store.
	//
	// Keys that do not correspond to blob entries are ignored. An
	// error IS NOT returned.
	Del(keys []string) error

	// Get returns the blob for the provided key.
	//
	// An ErrNotFound error is returned if the key does not correspond
	// to an entry.
	Get(key string) ([]byte, error)

	// GetBatch returns the blobs for the provided keys.
	//
	// An entry will not exist in the returned map if for any blobs
	// that are not found. It is the responsibility of the caller to
	// ensure a blob was returned for all provided keys. An error is
	// not returned.
	GetBatch(keys []string) (map[string][]byte, error)

	// Rollback aborts the transaction.
	Rollback() error

	// Commit commits the transaction.
	Commit() error
}

// Getter describes the get methods that are present on both the BlobKV
// interface and the Tx interface. This allows the same code to be used for
// executing individual get requests against the BlobKV and for executing
// get requests that are part of a Tx.
type Getter interface {
	Get(key string) ([]byte, error)
	GetBatch(keys []string) (map[string][]byte, error)
}

// BlobEntry is the structure used to store data in the key-value store.
type BlobEntry struct {
	Digest   string `json:"digest"`   // SHA256 digest of data, hex encoded
	DataHint string `json:"datahint"` // Hint that describes data, base64 encoded
	Data     string `json:"data"`     // Data payload, base64 encoded
}

// NewBlobEntry returns a new BlobEntry.
func NewBlobEntry(dh DataHint, data []byte) (*BlobEntry, error) {
	dataHint, err := json.Marshal(dh)
	if err != nil {
		return nil, err
	}
	return &BlobEntry{
		Digest:   hex.EncodeToString(util.Digest(data)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}, nil
}

const (
	// DataTypeStructure describes a blob entry that contains a structure.
	DataTypeStructure = "struct"
)

// DataHint provides hints about a data blob. In practice we JSON encode
// this struture and stuff it into BlobEntry.DataHint.
type DataHint struct {
	Type       string `json:"type"`                // Type of data
	Descriptor string `json:"descriptor"`          // Description of the data
	ExtraData  string `json:"extradata,omitempty"` // Value to be freely used
}

// DecodeDataHint decodes and returns the BlobEntry DataHint.
func DecodeDataHint(be BlobEntry) (*DataHint, error) {
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var dh DataHint
	err = json.Unmarshal(b, &dh)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &dh, nil
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

// Decode decodes the BlobEntry base64 data payload and returns it as a byte
// slice. The coherency of the data is verified during this process.
func Decode(be BlobEntry, dataDescriptor string) ([]byte, error) {
	// Decode and verify the data hint
	dh, err := DecodeDataHint(be)
	if err != nil {
		return nil, err
	}
	if dh.Descriptor != dataDescriptor {
		return nil, errors.Errorf("unexpected data descriptor: "+
			"got %v, want %v", dh.Descriptor, dataDescriptor)
	}

	// Decode and verify the data payload
	b, err := base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, errors.Errorf("data is not coherent: "+
			"got %x, want %x", util.Digest(b), digest)
	}

	return b, nil
}
