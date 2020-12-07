// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrutil/v3"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/robfig/cron"
)

var (
	defaultTestDir     = dcrutil.AppDataDir("politeiadtest", false)
	defaultTestDataDir = filepath.Join(defaultTestDir, "data")
)

// newTestTClient provides a trillian client implementation used for
// testing. It implements the TClient interface, which includes all major
// tree operations used in the tlog backend.
func newTestTClient(t *testing.T) (*testTClient, error) {
	// Create trillian private key
	key, err := keys.NewFromSpec(&keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{},
	})
	if err != nil {
		return nil, err
	}
	keyDer, err := der.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	ttc := testTClient{
		trees:  make(map[int64]*trillian.Tree),
		leaves: make(map[int64][]*trillian.LogLeaf),
		privateKey: &keyspb.PrivateKey{
			Der: keyDer,
		},
	}

	return &ttc, nil
}

// newTestTlog returns a tlog used for testing.
func newTestTlog(t *testing.T, id string) (*tlog, error) {
	// Setup key-value store with test dir
	fp := filepath.Join(defaultTestDataDir, id)
	err := os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	tclient, err := newTestTClient(t)
	if err != nil {
		return nil, err
	}

	tlog := tlog{
		id:            id,
		dcrtimeHost:   v1.DefaultTestnetTimeHost,
		encryptionKey: nil,
		trillian:      tclient,
		store:         store,
		cron:          cron.New(),
	}

	return &tlog, nil
}

// newTestTlogBackend returns a tlog backend for testing. It wraps
// tlog and trillian client, providing the framework needed for
// writing tlog backend tests.
func newTestTlogBackend(t *testing.T) (*tlogBackend, error) {
	tlogVetted, err := newTestTlog(t, "vetted")
	if err != nil {
		return nil, err
	}
	tlogUnvetted, err := newTestTlog(t, "unvetted")
	if err != nil {
		return nil, err
	}

	tlogBackend := tlogBackend{
		homeDir:       defaultTestDir,
		dataDir:       defaultTestDataDir,
		unvetted:      tlogUnvetted,
		vetted:        tlogVetted,
		plugins:       make(map[string]plugin),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
		inv: recordInventory{
			unvetted: make(map[backend.MDStatusT][]string),
			vetted:   make(map[backend.MDStatusT][]string),
		},
	}

	err = tlogBackend.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &tlogBackend, nil
}
