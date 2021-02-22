// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"io/ioutil"
	"testing"

	"github.com/decred/politeia/politeiad/backend/tstorebe/store/fs"
	"github.com/marcopeereboom/sbox"
)

func newTestTstore(t *testing.T, tstoreID, dataDir string, encrypt bool) *Tstore {
	t.Helper()

	// Setup datadir for this tstore instance
	var err error
	dataDir, err = ioutil.TempDir(dataDir, tstoreID)
	if err != nil {
		t.Fatal(err)
	}

	// Setup key-value store
	fp, err := ioutil.TempDir(dataDir, defaultStoreDirname)
	if err != nil {
		t.Fatal(err)
	}
	store := fs.New(fp)

	// Setup encryptin key if specified
	var ek *encryptionKey
	if encrypt {
		key, err := sbox.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		ek = newEncryptionKey(key)
	}

	return &Tstore{
		id:            tstoreID,
		encryptionKey: ek,
		trillian:      newTestTClient(t),
		store:         store,
	}
}

// NewTestTstoreEncrypted returns a tstore instance that encrypts all data blobs
// and that has been setup for testing.
func NewTestTstoreEncrypted(t *testing.T, tstoreID, dataDir string) *Tstore {
	return newTestTstore(t, tstoreID, dataDir, true)
}

// NewTestTstoreUnencrypted returns a tstore instance that save all data blobs
// as plaintext and that has been setup for testing.
func NewTestTstoreUnencrypted(t *testing.T, tstoreID, dataDir string) *Tstore {
	return newTestTstore(t, tstoreID, dataDir, false)
}
