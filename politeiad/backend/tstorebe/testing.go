// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiad/backend/tstorebe/tstore"
)

// NewTestTstoreBackend returns a tstoreBackend that is setup for testing and a
// closure that cleans up all test data when invoked.
func NewTestTstoreBackend(t *testing.T) (*tstoreBackend, func()) {
	t.Helper()

	// Setup home dir and data dir
	homeDir, err := ioutil.TempDir("", "tstorebackend.test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(homeDir, "data")

	tstoreBackend := tstoreBackend{
		homeDir:       homeDir,
		dataDir:       dataDir,
		unvetted:      tstore.NewTestTstoreUnencrypted(t, dataDir, "unvetted"),
		vetted:        tstore.NewTestTstoreEncrypted(t, dataDir, "vetted"),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
	}

	return &tstoreBackend, func() {
		err = os.RemoveAll(homeDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
