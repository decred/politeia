// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
)

func TestDeriveTlogKey(t *testing.T) {
	// Setup a localdb kv store
	appDir, err := ioutil.TempDir("", "tstore.test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(appDir)
		if err != nil {
			t.Fatal(err)
		}
	}()
	storeDir := filepath.Join(appDir, "store")
	kvstore, err := localdb.New(appDir, storeDir)
	if err != nil {
		t.Fatal(err)
	}

	// Key derivation params should be created and saved to the kv
	// store the first time the key is derived.
	pass := "testpasshrase"
	key1, err := deriveTlogKey(kvstore, pass)
	if err != nil {
		t.Fatal(err)
	}

	// Subsequent calls should use the existing derivation params and
	// return the same key. This function will error if the derived
	// keys are not the same.
	key2, err := deriveTlogKey(kvstore, pass)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity check
	if key1.String() != key2.String() {
		t.Fatalf("different key was returned without any errors")
	}
}
