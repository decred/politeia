// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"io/ioutil"
	"testing"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
	"github.com/marcopeereboom/sbox"
)

func NewTestTstore(t *testing.T, dataDir string) *Tstore {
	t.Helper()

	// Setup datadir for this tstore instance
	dataDir, err := ioutil.TempDir(dataDir, "tstore.test")
	if err != nil {
		t.Fatal(err)
	}

	// Setup key-value store
	fp, err := ioutil.TempDir(dataDir, defaultStoreDirname)
	if err != nil {
		t.Fatal(err)
	}
	store, err := localdb.New(fp)
	if err != nil {
		t.Fatal(err)
	}

	// Setup encryptin key if specified
	key, err := sbox.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := newEncryptionKey(key)

	return &Tstore{
		encryptionKey: ek,
		trillian:      newTestTClient(t),
		store:         store,
	}
}
