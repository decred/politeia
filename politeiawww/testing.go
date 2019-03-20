// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// errToStr returns the string representation of the error. If the error is a
// UserError then the human readable error message is returned instead of the
// error code.
func errToStr(e error) string {
	if e == nil {
		return "nil"
	}

	userErr, ok := e.(www.UserError)
	if ok {
		return www.ErrorStatus[userErr.ErrorCode]
	}

	return e.Error()
}

// newPostReq returns an httptest post request that was created using the
// passed in data.
func newPostReq(t *testing.T, route string, body interface{}) *http.Request {
	t.Helper()

	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return httptest.NewRequest(http.MethodPost, route,
		bytes.NewReader(b))
}

// newUser creates a new user using randomly generated user credentials and
// inserts the user into the database.  The user details and the full user
// identity are returned.
func newUser(t *testing.T, p *politeiawww, isVerified, isAdmin bool) (*user.User, *identity.FullIdentity) {
	t.Helper()

	// Create a new user identity
	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate random bytes to be used as user credentials
	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Setup user
	pass, err := p.hashPassword(hex.EncodeToString(r))
	if err != nil {
		t.Fatalf("%v", err)
	}

	pubkey := hex.EncodeToString(id.Public.Key[:])
	_, err = validatePubkey(pubkey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	token, expiry, err := generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}

	u := user.User{
		Email:          hex.EncodeToString(r) + "@example.com",
		Username:       hex.EncodeToString(r),
		HashedPassword: pass,
		Admin:          isAdmin,
	}

	setNewUserVerificationAndIdentity(&u, token, expiry,
		false, id.Public.Key[:])

	// Set user verification status
	if isVerified {
		u.NewUserVerificationToken = nil
		u.NewUserVerificationExpiry = 0
		u.ResendNewUserVerificationExpiry = 0
	} else {
		tb, expiry, err := generateVerificationTokenAndExpiry()
		if err != nil {
			t.Fatalf("%v", err)
		}
		u.NewUserVerificationToken = tb
		u.NewUserVerificationExpiry = expiry
	}

	// Add user to database
	err = p.db.UserNew(u)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add the user to the politeiawww in-memory [pubkey]userID
	// cache. Since the userID is generated in the database layer
	// we need to lookup the user in order to get the userID.
	usr, err := p.db.UserGet(u.Email)
	if err != nil {
		t.Fatalf("%v", err)
	}

	p.setUserPubkeyAssociaton(usr, pubkey)

	// Add paywall info to the user record
	err = p.GenerateNewUserPaywall(usr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Lookup user record one more time so that
	// we return a user object with the paywall
	// details filled in.
	usr, err = p.db.UserGet(usr.Email)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return usr, id
}

func cleanupTestPoliteiawww(t *testing.T, p *politeiawww) {
	t.Helper()

	err := p.db.Close()
	if err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = logRotator.Close()
	if err != nil {
		t.Fatalf("close log rotator: %v", err)
	}

	// DataDir is a temp directory that needs
	// to be removed.
	err = os.RemoveAll(p.cfg.DataDir)
	if err != nil {
		t.Fatalf("remove tmp dir: %v", err)
	}
}

// newTestPoliteiawww returns a new politeiawww context that is setup for
// testing.
func newTestPoliteiawww(t *testing.T) *politeiawww {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in cleanupTestPoliteiawww().
	dir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Setup config
	cfg := &config{
		DataDir:       dir,
		PaywallAmount: 1e7,
		PaywallXpub:   "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
		TestNet:       true,
	}

	// Setup database
	db, err := localdb.New(filepath.Join(cfg.DataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	// Setup smtp
	smtp, err := newSMTP("", "", "", "")
	if err != nil {
		t.Fatalf("setup SMTP: %v", err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}
	sessionsDir := filepath.Join(cfg.DataDir, "sessions")
	err = os.MkdirAll(sessionsDir, 0700)
	if err != nil {
		t.Fatalf("make sessions dir: %v", err)
	}
	store := sessions.NewFilesystemStore(sessionsDir, cookieKey)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	// Setup logging
	initLogRotator(filepath.Join(cfg.DataDir, "politeiawww.test.log"))
	setLogLevels("off")

	// Create politeiawww context
	p := politeiawww{
		cfg:             cfg,
		db:              db,
		params:          &chaincfg.TestNet3Params,
		router:          mux.NewRouter(),
		store:           store,
		smtp:            smtp,
		test:            true,
		userPubkeys:     make(map[string]string),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentScores:   make(map[string]int64),
	}

	// Setup routes
	p.setPoliteiaWWWRoutes()
	p.setUserWWWRoutes()

	return &p
}
