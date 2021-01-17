// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogclient

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// Client provides an API for plugins to interact with a tlog instance.
// Plugins are allowed to save, delete, and get plugin data to/from the tlog
// backend. Editing plugin data is not allowed.
type Client interface {
	// BlobSave saves a BlobEntry to the tlog instance. The BlobEntry
	// will be encrypted prior to being written to disk if the tlog
	// instance has an encryption key set. The digest of the data,
	// i.e. BlobEntry.Digest, can be thought of as the blob ID and can
	// be used to get/del the blob from tlog.
	BlobSave(treeID int64, dataType string, be store.BlobEntry) error

	// BlobsDel deletes the blobs that correspond to the provided
	// digests.
	BlobsDel(treeID int64, digests [][]byte) error

	// Blobs returns the blobs that correspond to the provided digests.
	// If a blob does not exist it will not be included in the returned
	// map.
	Blobs(treeID int64, digests [][]byte) (map[string]store.BlobEntry, error)

	// BlobsByDataType returns all blobs that match the data type. The
	// blobs will be ordered from oldest to newest.
	BlobsByDataType(treeID int64, keyPrefix string) ([]store.BlobEntry, error)

	// DigestsByDataType returns the digests of all blobs that match
	// the data type.
	DigestsByDataType(treeID int64, dataType string) ([][]byte, error)

	// Timestamp returns the timestamp for the blob that correpsonds
	// to the digest.
	Timestamp(treeID int64, digest []byte) (*backend.Timestamp, error)
}
