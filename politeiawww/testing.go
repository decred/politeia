// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	www "github.com/decred/politeia/politeiawww/api/v1"
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
//func createBackend(t *testing.T) *_backend {
//	t.Helper()
//
//	// Setup config
//	dir, err := ioutil.TempDir("", "politeiawww.test")
//	if err != nil {
//		t.Fatalf("open tmp dir: %v", err)
//	}
//	defer os.RemoveAll(dir)
//
//	cfg := &config{
//		DataDir:       filepath.Join(dir, "data"),
//		PaywallAmount: 1e7,
//		PaywallXpub:   "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
//		TestNet:       true,
//	}
//
//	// Setup database
//	db, err := localdb.New(cfg.DataDir)
//	if err != nil {
//		t.Fatalf("setup database: %v", err)
//	}
//
//	return &_backend{
//		db:              db,
//		params:          &chaincfg.TestNet3Params,
//		test:            true,
//		userPubkeys:     make(map[string]string),
//		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
//		commentScores:   make(map[string]int64),
//	}
//}

// createNewUser creates a new user in the backend database using randomly
// generated user credentials then returns the NewUser object and the full
// identity for the user.
//func createNewUser(t *testing.T, b *_backend) (*www.NewUser, *identity.FullIdentity) {
//	t.Helper()
//
//	id, err := identity.New()
//	if err != nil {
//		t.Fatalf("%v", err)
//	}
//
//	r, err := util.Random(int(www.PolicyMinPasswordLength))
//	if err != nil {
//		t.Fatalf("%v", err)
//	}
//
//	nu := www.NewUser{
//		Email:     hex.EncodeToString(r) + "@example.com",
//		Username:  hex.EncodeToString(r),
//		Password:  hex.EncodeToString(r),
//		PublicKey: hex.EncodeToString(id.Public.Key[:]),
//	}
//
//	panic("ProcessNewUser")
//	// XXX this needs to be rethough since we are mixing front and backend
//	//_, err = b.ProcessNewUser(nu)
//	//if err != nil {
//	//	t.Fatalf("ProcessNewUser: %v", err)
//	//}
//
//	return &nu, id
//}
