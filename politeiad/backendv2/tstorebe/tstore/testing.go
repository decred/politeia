// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"os"
	"testing"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tlog"
)

// NewTestTstore returns a tstore instance that is setup for testing.
func NewTestTstore(t *testing.T, dataDir string) *Tstore {
	t.Helper()

	// Setup datadir for this tstore instance
	dataDir, err := os.MkdirTemp(dataDir, "tstore.test")
	if err != nil {
		t.Fatal(err)
	}

	// Setup key-value store
	fp, err := os.MkdirTemp(dataDir, storeDirname)
	if err != nil {
		t.Fatal(err)
	}
	store, err := localdb.New(dataDir, fp)
	if err != nil {
		t.Fatal(err)
	}

	return &Tstore{
		tlog:  tlog.NewTestClient(t),
		store: store,
	}
}
