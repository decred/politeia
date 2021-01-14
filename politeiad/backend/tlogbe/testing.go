// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
)

// newTestTlogBackend returns a tlog backend for testing. It wraps
// tlog and trillian client, providing the framework needed for
// writing tlog backend tests.
func newTestTlogBackend(t *testing.T) (*tlogBackend, func()) {
	t.Helper()

	testDir, err := ioutil.TempDir("", "tlog.backend.test")
	if err != nil {
		t.Fatal(err)
	}
	testDataDir := filepath.Join(testDir, "data")

	tlogBackend := tlogBackend{
		activeNetParams: chaincfg.TestNet3Params(),
		homeDir:         testDir,
		dataDir:         testDataDir,
		unvetted:        tlog.NewTestTlog(t, testDir, "unvetted"),
		vetted:          tlog.NewTestTlog(t, testDir, "vetted"),
		prefixes:        make(map[string][]byte),
		vettedTreeIDs:   make(map[string]int64),
		inv: recordInventory{
			unvetted: make(map[backend.MDStatusT][]string),
			vetted:   make(map[backend.MDStatusT][]string),
		},
	}

	err = tlogBackend.setup()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	return &tlogBackend, func() {
		err = os.RemoveAll(testDir)
		if err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
	}
}
