// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package store

import "errors"

var (
	ErrNotFound = errors.New("not found")
)

// Ops specifies multiple Blob operations that should be performed atomically.
type Ops struct {
	Put map[string][]byte
	Del []string
}

// Blob represents a blob key-value store.
type Blob interface {
	Put(key string, blob []byte) error              // Store blob
	Get(key string) ([]byte, error)                 // Get blob by identifier
	Del(key string) error                           // Attempt to delete object
	Enum(func(key string, blob []byte) error) error // Enumerate over all objects
	Multi(Ops) error                                // Perform multiple operations atomically
}
