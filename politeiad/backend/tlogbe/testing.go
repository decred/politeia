// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
)

// NewTestTlogBackend returns a tlogBackend that is setup for testing and a
// closure that cleans up all test data when invoked.
func NewTestTlogBackend(t *testing.T) (*tlogBackend, func()) {
	t.Helper()

	// Setup home dir and data dir
	homeDir, err := ioutil.TempDir("", "tlogbackend.test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(homeDir, "data")

	tlogBackend := tlogBackend{
		homeDir:       homeDir,
		dataDir:       dataDir,
		unvetted:      tlog.NewTestTlogUnencrypted(t, dataDir, "unvetted"),
		vetted:        tlog.NewTestTlogEncrypted(t, dataDir, "vetted"),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
	}

	return &tlogBackend, func() {
		err = os.RemoveAll(homeDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
