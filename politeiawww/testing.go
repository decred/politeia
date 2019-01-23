// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database/leveldb"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// convetErrorToMsg returns the string representation of the error. If the
// error is a UserError then the human readable error message is returned
// instead of the error code.
func convertErrorToMsg(e error) string {
	if e == nil {
		return "nil"
	}

	userErr, ok := e.(www.UserError)
	if ok {
		return www.ErrorStatus[userErr.ErrorCode]
	}

	return e.Error()
}

// createBackend creates a backend that can be used for testing purposes.
func createBackend(t *testing.T) *backend {
	t.Helper()

	// Setup config
	dir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	cfg := &config{
		DataDir:       filepath.Join(dir, "data"),
		PaywallAmount: 1e7,
		PaywallXpub:   "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
		TestNet:       true,
	}

	// Create a database key
	keyFilename := filepath.Join(dir, defaultDBKeyFilename)
	err = database.NewEncryptionKey(keyFilename)
	if err != nil {
		t.Fatalf("new encription key: %v", err)
	}
	key, err := database.LoadEncryptionKey(keyFilename)
	if err != nil {
		t.Fatalf("load encryption key: %v", err)
	}

	// Setup database
	err = leveldb.CreateLevelDB(cfg.DataDir)
	if err != nil {
		t.Fatalf("lreate level db: %v", err)
	}

	db, err := leveldb.NewLevelDB(cfg.DataDir, key, nil)
	if err != nil {
		t.Fatalf("new leveldb %v", err)
	}

	return &backend{
		db:              db,
		cfg:             cfg,
		params:          &chaincfg.TestNet3Params,
		test:            true,
		userPubkeys:     make(map[string]string),
		userEmail:       make(map[string]string),
		userUsername:    make(map[string]string),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentScores:   make(map[string]int64),
	}
}

// createNewUser creates a new user in the backend database using randomly
// generated user credentials then returns the NewUser object and the full
// identity for the user.
func createNewUser(t *testing.T, b *backend) (*www.NewUser, *identity.FullIdentity) {
	t.Helper()

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}

	nu := www.NewUser{
		Email:     hex.EncodeToString(r) + "@example.com",
		Username:  hex.EncodeToString(r),
		Password:  hex.EncodeToString(r),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	_, err = b.ProcessNewUser(nu)
	if err != nil {
		t.Fatalf("ProcessNewUser: %v", err)
	}

	return &nu, id
}
