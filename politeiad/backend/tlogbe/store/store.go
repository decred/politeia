// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package store

import "errors"

var (
	// ErrNotFound is emitted when a blob is not found.
	ErrNotFound = errors.New("not found")
)

type Ops struct {
	Put map[string][]byte
	Del []string
}

type Blob interface {
	Get(string) ([]byte, error)
	Put(string, []byte) error
	Del(key string) error
	Enum(func(key string, blob []byte) error) error
	Batch(Ops) error
}

// Blob represents a blob key-value store.
type Blob_ interface {
	// Get returns blobs from the store. An entry will not exist in the
	// returned map if for any blobs that are not found. It is the
	// responsibility of the caller to ensure a blob was returned for
	// all provided keys.
	Get(keys []string) (map[string][]byte, error)

	// Put saves the provided blobs to the store. The keys for the
	// blobs are returned using the same odering that the blobs were
	// provided in. This operation is performed atomically.
	Put(blobs [][]byte) ([]string, error)

	// Del deletes the provided blobs from the store. This operation
	// is performed atomically.
	Del(keys []string) error

	// Enum enumerates over all blobs in the store, invoking the
	// provided function for each blob.
	Enum(func(key string, blob []byte) error) error

	// Closes closes the blob store connection.
	Close()
}
