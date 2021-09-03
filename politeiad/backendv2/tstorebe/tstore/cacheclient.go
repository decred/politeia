// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/pkg/errors"
)

var (
	_ plugins.CacheClient = (*cacheClient)(nil)
)

// cacheClient satisfies the plugins CacheClient interface.
type cacheClient struct {
	id      string // Caller ID used for logging
	encrypt bool   // Encrypt data on writes

	// writer is used for all write operations. Write operations are
	// atomic.
	//
	// This will be nil when the client is initialized by a plugin
	// read command.
	writer store.Tx

	// reader is used for all read operations.
	//
	// reader will be a store Tx when the client is initialized by
	// a plugin write command. Operations will be atomic.
	//
	// reader will be a store BlobKV when the client is initialized
	// by a plugin read command. Operations WILL NOT be atomic.
	reader store.Getter
}

// newCacheClient returns a new cacheClient.
func newCacheClient(id string, encrypt bool, tx store.Tx, g store.Getter) *cacheClient {
	return &cacheClient{
		id:      id,
		encrypt: encrypt,
		writer:  tx,
		reader:  g,
	}
}

// Insert inserts a new entry into the cache store for each of the provided
// key-value pairs.
//
// A store.ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
func (c *cacheClient) Insert(blobs map[string][]byte) error {
	log.Tracef("%v Cache Insert: %v blobs, encrypted %v",
		c.id, len(blobs), c.encrypt)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.writer.Insert(blobs, c.encrypt)
}

// Update updates the provided key-value pairs in the cache.
//
// A store.ErrNotFound is returned if the caller attempts to update an entry
// that does not exist.
func (c *cacheClient) Update(blobs map[string][]byte) error {
	log.Tracef("%v Cache Update: %v blobs, encrypted %v",
		c.id, len(blobs), c.encrypt)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.writer.Update(blobs, c.encrypt)
}

// Del deletes the provided entries from the cache.
//
// Keys that do not correspond to blob entries are ignored. An error IS NOT
// returned.
func (c *cacheClient) Del(keys []string) error {
	log.Tracef("%v Cache Del: %v", c.id, keys)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.writer.Del(keys)
}

// Get returns the cached blob for the provided key.
//
// A store.ErrNotFound error is returned if the key does not correspond to an
// entry.
func (c *cacheClient) Get(key string) ([]byte, error) {
	log.Tracef("%v Cache Get: %v", c.id, key)

	return c.writer.Get(key)
}

// GetBatch returns the cached blobs for the provided keys.
//
// An entry will not exist in the returned map if for any blobs that are not
// found. It is the responsibility of the caller to ensure a blob was returned
// for all provided keys. An error is not returned.
func (c *cacheClient) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("%v Cache GetBatch: %v", c.id, keys)

	return c.writer.GetBatch(keys)
}
