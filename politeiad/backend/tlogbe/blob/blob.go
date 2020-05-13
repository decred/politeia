// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blob

import "errors"

var (
	ErrNotFound = errors.New("not found")
)

type Blob interface {
	Put(key string, blob []byte) error              // Store blob
	PutMulti(blobs map[string][]byte) error         // Store multiple blobs atomically
	Get(key string) ([]byte, error)                 // Get blob by identifier
	Del(key string) error                           // Attempt to delete object
	Enum(func(key string, blob []byte) error) error // Enumerate over all objects
}
