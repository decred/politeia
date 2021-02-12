// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"io/ioutil"
	"testing"

	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/marcopeereboom/sbox"
)

func newTestTlog(t *testing.T, tlogID, dataDir string, encrypt bool) *Tlog {
	t.Helper()

	// Setup datadir for this tlog instance
	var err error
	dataDir, err = ioutil.TempDir(dataDir, tlogID)
	if err != nil {
		t.Fatal(err)
	}

	// Setup key-value store
	fp, err := ioutil.TempDir(dataDir, defaultStoreDirname)
	if err != nil {
		t.Fatal(err)
	}
	store := filesystem.New(fp)

	// Setup encryptin key if specified
	var ek *encryptionKey
	if encrypt {
		key, err := sbox.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		ek = newEncryptionKey(key)
	}

	return &Tlog{
		id:            tlogID,
		encryptionKey: ek,
		trillian:      newTestTClient(t),
		store:         store,
	}
}

// NewTestTlogEncrypted returns a tlog instance that encrypts all data blobs
// and that has been setup for testing.
func NewTestTlogEncrypted(t *testing.T, tlogID, dataDir string) *Tlog {
	return newTestTlog(t, tlogID, dataDir, true)
}

// NewTestTlogUnencrypted returns a tlog instance that save all data blobs
// as plaintext and that has been setup for testing.
func NewTestTlogUnencrypted(t *testing.T, tlogID, dataDir string) *Tlog {
	return newTestTlog(t, tlogID, dataDir, false)
}
