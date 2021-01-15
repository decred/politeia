// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testclient

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// testClient implements the tlogclient.Client interface and is used for
// plugin testing.
type testClient struct{}

// BlobSave saves a BlobEntry to the tlog backend. The merkle leaf hash for the
// blob will be returned. This merkle leaf hash can be though of as the blob ID
// and can be used to retrieve or delete the blob.
func (t *testClient) BlobSave(treeID int64, keyPrefix string, be store.BlobEntry) ([]byte, error) {
	return nil, nil
}

// BlobsDel deletes the blobs that correspond to the provided merkle leaf
// hashes.
func (t *testClient) BlobsDel(treeID int64, merkles [][]byte) error {
	return nil
}

// BlobsByMerkle returns the blobs with the provided merkle leaf hashes. If a
// blob does not exist it will not be included in the returned map.
func (t *testClient) BlobsByMerkle(treeID int64, merkles [][]byte) (map[string][]byte, error) {
	return nil, nil
}

// BlobsByKeyPrefix returns all blobs that match the key prefix.
func (t *testClient) BlobsByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error) {
	return nil, nil
}

// MerklesByKeyPrefix returns the merkle leaf hashes for all blobs that match
// the key prefix.
func (t *testClient) MerklesByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error) {
	return nil, nil
}

// Timestamp returns the timestamp for the blob that correpsonds to the merkle
// leaf hash.
func (t *testClient) Timestamp(treeID int64, merkle []byte) (*backend.Timestamp, error) {
	return nil, nil
}

// New returns a new testClient.
func New() *testClient {
	return &testClient{}
}
