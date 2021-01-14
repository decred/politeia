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

// NewTestTlog returns a tlog used for testing.
func NewTestTlog(t *testing.T, dir, id string) *Tlog {
	t.Helper()

	dir, err := ioutil.TempDir(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sbox.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tclient, err := newTestTClient()
	if err != nil {
		t.Fatal(err)
	}

	return &Tlog{
		id:            id,
		dcrtime:       nil,
		encryptionKey: newEncryptionKey(key),
		trillian:      tclient,
		store:         filesystem.New(dir),
	}
}
