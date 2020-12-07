// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"fmt"
)

// TODO verify writes only accept full length tokens

// tlogClient provides an API for the plugins to use to interact with the tlog
// backend. Plugins are allowed to save, delete, and get plugin data to/from
// the tlog backend. Editing plugin data is not allowed.
type tlogClient interface {
	// save saves the provided blobs to the tlog backend. Note, hashes
	// contains the hashes of the data encoded in the blobs. The hashes
	// must share the same ordering as the blobs.
	save(tlogID string, token []byte, keyPrefix string,
		blobs, hashes [][]byte, encrypt bool) ([][]byte, error)

	// del deletes the blobs that correspond to the provided merkle
	// leaf hashes.
	del(tlogID string, token []byte, merkles [][]byte) error

	// blobsByMerkle returns the blobs with the provided merkle leaf
	// hashes. If a blob does not exist it will not be included in the
	// returned map.
	blobsByMerkle(tlogID string, token []byte,
		merkles [][]byte) (map[string][]byte, error)

	// blobsByKeyPrefix returns all blobs that match the provided key
	// prefix.
	blobsByKeyPrefix(tlogID string, token []byte,
		keyPrefix string) ([][]byte, error)
}

var (
	_ tlogClient = (*backendClient)(nil)
)

// backendClient implements the tlogClient interface.
type backendClient struct {
	backend *tlogBackend
}

// tlogByID returns the tlog instance that corresponds to the provided ID.
func (c *backendClient) tlogByID(tlogID string) (*tlog, error) {
	switch tlogID {
	case tlogIDUnvetted:
		return c.backend.unvetted, nil
	case tlogIDVetted:
		return c.backend.vetted, nil
	}
	return nil, fmt.Errorf("unknown tlog id '%v'", tlogID)
}

// treeIDFromToken returns the treeID for the provided tlog instance ID and
// token.
func (c *backendClient) treeIDFromToken(tlogID string, token []byte) (int64, error) {
	if len(token) == tokenPrefixSize() {
		// This is a token prefix. Get the full token from the cache.
		var ok bool
		token, ok = c.backend.fullLengthToken(token)
		if !ok {
			return 0, errRecordNotFound
		}
	}

	switch tlogID {
	case tlogIDUnvetted:
		return treeIDFromToken(token), nil
	case tlogIDVetted:
		treeID, ok := c.backend.vettedTreeIDFromToken(token)
		if !ok {
			return 0, errRecordNotFound
		}
		return treeID, nil
	}
	return 0, fmt.Errorf("unknown tlog id '%v'", tlogID)
}

// save saves the provided blobs to the tlog backend. Note, hashes contains the
// hashes of the data encoded in the blobs. The hashes must share the same
// ordering as the blobs.
func (c *backendClient) save(tlogID string, token []byte, keyPrefix string, blobs, hashes [][]byte, encrypt bool) ([][]byte, error) {
	log.Tracef("tlogClient save: %x %v %v %x", token, keyPrefix, encrypt, hashes)

	// Get tlog instance
	tlog, err := c.tlogByID(tlogID)
	if err != nil {
		return nil, err
	}

	// Get tree ID
	treeID, err := c.treeIDFromToken(tlogID, token)
	if err != nil {
		return nil, err
	}

	// Save blobs
	return tlog.blobsSave(treeID, keyPrefix, blobs, hashes, encrypt)
}

// del deletes the blobs that correspond to the provided merkle leaf hashes.
func (c *backendClient) del(tlogID string, token []byte, merkles [][]byte) error {
	log.Tracef("tlogClient del: %x %x", token, merkles)

	// Get tlog instance
	tlog, err := c.tlogByID(tlogID)
	if err != nil {
		return err

	}

	// Get tree ID
	treeID, err := c.treeIDFromToken(tlogID, token)
	if err != nil {
		return err
	}

	// Delete blobs
	return tlog.blobsDel(treeID, merkles)
}

// blobsByMerkle returns the blobs with the provided merkle leaf hashes.
//
// If a blob does not exist it will not be included in the returned map. It is
// the responsibility of the caller to check that a blob is returned for each
// of the provided merkle hashes.
func (c *backendClient) blobsByMerkle(tlogID string, token []byte, merkles [][]byte) (map[string][]byte, error) {
	log.Tracef("tlogClient blobsByMerkle: %x %x", token, merkles)

	// Get tlog instance
	tlog, err := c.tlogByID(tlogID)
	if err != nil {
		return nil, err
	}

	// Get tree ID
	treeID, err := c.treeIDFromToken(tlogID, token)
	if err != nil {
		return nil, err
	}

	// Get blobs
	return tlog.blobsByMerkle(treeID, merkles)
}

// blobsByKeyPrefix returns all blobs that match the provided key prefix.
func (c *backendClient) blobsByKeyPrefix(tlogID string, token []byte, keyPrefix string) ([][]byte, error) {
	log.Tracef("tlogClient blobsByKeyPrefix: %x %x", token, keyPrefix)

	// Get tlog instance
	tlog, err := c.tlogByID(tlogID)
	if err != nil {
		return nil, err
	}

	// Get tree ID
	treeID, err := c.treeIDFromToken(tlogID, token)
	if err != nil {
		return nil, err
	}

	// Get blobs
	return tlog.blobsByKeyPrefix(treeID, keyPrefix)
}

// newBackendClient returns a new backendClient.
func newBackendClient(tlog *tlogBackend) *backendClient {
	return &backendClient{
		backend: tlog,
	}
}
