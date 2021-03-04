// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
)

// NewTestTstoreBackend returns a tstoreBackend that is setup for testing and a
// closure that cleans up all test data when invoked.
func NewTestTstoreBackend(t *testing.T) (*tstoreBackend, func()) {
	t.Helper()

	// Setup home dir and data dir
	appDir, err := ioutil.TempDir("", "tstorebackend.test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(appDir, "data")

	tstoreBackend := tstoreBackend{
		appDir:     appDir,
		dataDir:    dataDir,
		tstore:     tstore.NewTestTstore(t, dataDir),
		prefixes:   make(map[string][]byte),
		recordMtxs: make(map[string]*sync.Mutex),
	}

	return &tstoreBackend, func() {
		err = os.RemoveAll(appDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
