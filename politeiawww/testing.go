// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/thi4go/politeia/politeiad/cache/testcache"
	"github.com/thi4go/politeia/politeiad/testpoliteiad"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/thi4go/politeia/politeiawww/user/localdb"
	"github.com/thi4go/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
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

func payRegistrationFee(t *testing.T, p *politeiawww, u *user.User) {
	t.Helper()

	u.NewUserPaywallAmount = 0
	u.NewUserPaywallTx = "cleared_during_testing"
	u.NewUserPaywallPollExpiry = 0

	err := p.db.UserUpdate(*u)
	if err != nil {
		t.Fatal(err)
	}
}

func addProposalCredits(t *testing.T, p *politeiawww, u *user.User, quantity int) {
	t.Helper()

	c := make([]user.ProposalCredit, quantity)
	ts := time.Now().Unix()
	for i := 0; i < quantity; i++ {
		c[i] = user.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: ts,
			TxID:          "created_during_testing",
		}
	}
	u.UnspentProposalCredits = append(u.UnspentProposalCredits, c...)

	err := p.db.UserUpdate(*u)
	if err != nil {
		t.Fatal(err)
	}
}

// newUser creates a new user using randomly generated user credentials and
// inserts the user into the database.  The user details and the full user
// identity are returned.
func newUser(t *testing.T, p *politeiawww, isVerified, isAdmin bool) (*user.User, *identity.FullIdentity) {
	t.Helper()

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
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	u := user.User{
		ID:                        uuid.New(),
		Admin:                     isAdmin,
		Email:                     hex.EncodeToString(r) + "@example.com",
		Username:                  hex.EncodeToString(r),
		HashedPassword:            pass,
		NewUserVerificationToken:  tokenb,
		NewUserVerificationExpiry: expiry,
	}
	fid, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubkey := hex.EncodeToString(fid.Public.Key[:])
	id, err := user.NewIdentity(pubkey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = u.AddIdentity(*id)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if isVerified {
		u.NewUserVerificationToken = nil
		u.NewUserVerificationExpiry = 0
		err := u.ActivateIdentity(id.Key[:])
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	// Add user to database
	err = p.db.UserNew(u)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add the user to the politeiawww in-memory [email]userID
	// cache. Since the userID is generated in the database layer
	// we need to lookup the user in order to get the userID.
	usr, err := p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p.setUserEmailsCache(usr.Email, usr.ID)

	// Add paywall info to the user record
	err = p.GenerateNewUserPaywall(usr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Lookup user record one more time so that
	// we return a user object with the paywall
	// details filled in.
	usr, err = p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return usr, fid
}

// newTestPoliteiawww returns a new politeiawww context that is setup for
// testing and a closure that cleans up the test environment when invoked.
func newTestPoliteiawww(t *testing.T) (*politeiawww, func()) {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in the returned closure.
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Setup config
	cfg := &config{
		DataDir:       dataDir,
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
	smtp, err := newSMTP("", "", "", "", nil, false)
	if err != nil {
		t.Fatalf("setup SMTP: %v", err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}

	// Setup logging
	initLogRotator(filepath.Join(dataDir, "politeiawww.test.log"))
	setLogLevels("off")

	// Create politeiawww context
	p := politeiawww{
		cfg:             cfg,
		db:              db,
		cache:           testcache.New(),
		params:          &chaincfg.TestNet3Params,
		router:          mux.NewRouter(),
		sessions:        NewSessionStore(db, sessionMaxAge, cookieKey),
		smtp:            smtp,
		test:            true,
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentVotes:    make(map[string]counters),
	}

	// Setup routes
	p.setPoliteiaWWWRoutes()
	p.setUserWWWRoutes()

	// The cleanup is handled using a closure so that the temp dir
	// can be deleted using the local variable and not cfg.DataDir.
	// Using cfg.DataDir could be misused and lead to the deletion
	// of an unintended directory.
	return &p, func() {
		t.Helper()

		err := db.Close()
		if err != nil {
			t.Fatalf("close db: %v", err)
		}

		err = logRotator.Close()
		if err != nil {
			t.Fatalf("close log rotator: %v", err)
		}

		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatalf("remove tmp dir: %v", err)
		}
	}
}

// newTestPoliteiad returns a new TestPoliteiad context. The relevant
// politeiawww config params are updated with the TestPoliteiad info.
func newTestPoliteiad(t *testing.T, p *politeiawww) *testpoliteiad.TestPoliteiad {
	td := testpoliteiad.New(t, p.cache)
	p.cfg.RPCHost = td.URL
	p.cfg.Identity = td.PublicIdentity
	return td
}
