// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/politeiawww/legacy/user/localdb"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/util"
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

	var userErr www.UserError
	if errors.As(e, &userErr) {
		return www.ErrorStatus[userErr.ErrorCode]
	}

	return e.Error()
}

// newFilePNG creates a File that contains a png image. The png image is blank
// by default but can be filled in with random rgb colors by setting the
// addColor parameter to true. The png without color will be ~3kB. The png with
// color will be ~2MB.
func newFilePNG(t *testing.T, addColor bool) *www.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	// Fill in the pixels with random rgb colors in order to increase
	// the size of the image. This is used to create an image that
	// exceeds the maximum image size policy.
	if addColor {
		r := rand.New(rand.NewSource(255))
		for y := 0; y < img.Bounds().Max.Y-1; y++ {
			for x := 0; x < img.Bounds().Max.X-1; x++ {
				a := uint8(r.Float32() * 255)
				rgb := uint8(r.Float32() * 255)
				img.SetRGBA(x, y, color.RGBA{rgb, rgb, rgb, a})
			}
		}
	}

	err := png.Encode(b, img)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return &www.File{
		Name:    hex.EncodeToString(r) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

// newUser creates a new user using randomly generated user credentials and
// inserts the user into the database.  The user details and the full user
// identity are returned.
func newUser(t *testing.T, p *Politeiawww, isVerified, isAdmin bool) (*user.User, *identity.FullIdentity) {
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
	err = p.generateNewUserPaywall(usr)
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

// newCMSUser creates a new user using randomly generated user credentials and
// inserts the user into the database.  The user details and the full user
// identity are returned.
func newCMSUser(t *testing.T, p *Politeiawww, isAdmin bool, setGithubname bool, domain cms.DomainTypeT, contractorType cms.ContractorTypeT) *user.CMSUser {
	t.Helper()

	// Generate random bytes to be used as user credentials
	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}

	u := user.NewCMSUser{
		Email:                     hex.EncodeToString(r) + "@example.com",
		Username:                  hex.EncodeToString(r),
		NewUserVerificationToken:  nil,
		NewUserVerificationExpiry: 0,
		ContractorType:            int(cms.ContractorTypeDirect),
	}

	payload, err := user.EncodeNewCMSUser(u)
	if err != nil {
		t.Errorf("unable to encode new user %v", err)
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdNewCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		t.Errorf("unable to execute new cms user db request %v", err)
	}

	usr, err := p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("error getting user by username %v", err)
	}
	p.setUserEmailsCache(usr.Email, usr.ID)

	if isAdmin {
		usr.Admin = true
		err := p.db.UserUpdate(*usr)
		if err != nil {
			t.Fatalf("error updating user for admin %v", err)
		}
	}

	uu := user.UpdateCMSUser{
		ID:             usr.ID,
		Domain:         int(domain),
		ContractorType: int(contractorType),
	}
	if setGithubname {
		uu.GitHubName = "testGithub"
	}
	payload, err = user.EncodeUpdateCMSUser(uu)
	if err != nil {
		t.Errorf("unable to encode new user %v", err)
	}
	pc = user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		t.Errorf("unable to execute update cms user db request %v", err)
	}

	// Add the user to the politeiawww in-memory [email]userID
	// cache. Since the userID is generated in the database layer
	// we need to lookup the user in order to get the userID.
	usr, err = p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p.setUserEmailsCache(usr.Email, usr.ID)

	cmsUser, err := p.getCMSUserByIDRaw(usr.ID.String())
	if err != nil {
		t.Fatalf("%v", err)
	}

	return cmsUser
}

// newTestPoliteiawww returns a new politeiawww context that is setup for
// testing and a closure that cleans up the test environment when invoked.
func newTestPoliteiawww(t *testing.T) (*Politeiawww, func()) {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in the returned closure.
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Setup logging
	// initLogRotator(filepath.Join(dataDir, "politeiawww.test.log"))
	// setLogLevels("off")

	// Setup config
	xpub := "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFm" +
		"uMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx"
	fid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DataDir: dataDir,
		TestNet: true,
		LegacyConfig: config.LegacyConfig{
			PaywallAmount:   1e7,
			PaywallXpub:     xpub,
			VoteDurationMin: 2016,
			VoteDurationMax: 4032,
		},
		Identity: &fid.Public,
	}

	// Setup database
	db, err := localdb.New(filepath.Join(cfg.DataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	// Setup mail client
	mailClient, err := mail.NewClient("", "", "", "", "", false, 0, db)
	if err != nil {
		t.Fatal(err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}

	// Setup politeiawww context
	p := Politeiawww{
		cfg:             cfg,
		params:          chaincfg.TestNet3Params(),
		router:          mux.NewRouter(),
		auth:            mux.NewRouter(),
		sessions:        sessions.New(db, cookieKey),
		mail:            mailClient,
		db:              db,
		test:            true,
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
	}

	// Setup routes
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

		/*
			err = logRotator.Close()
			if err != nil {
				t.Fatalf("close log rotator: %v", err)
			}
		*/

		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatalf("remove tmp dir: %v", err)
		}
	}
}

// newTestCMSwww returns a new cmswww context that is setup for
// testing and a closure that cleans up the test environment when invoked.
func newTestCMSwww(t *testing.T) (*Politeiawww, func()) {
	t.Helper()

	// Make a temp directory for test data. Temp directory
	// is removed in the returned closure.
	dataDir, err := ioutil.TempDir("", "cmswww.test")
	if err != nil {
		t.Fatalf("open tmp dir: %v", err)
	}

	// Turn logging off
	logger.InitLogRotator(filepath.Join(dataDir, "cmswww.test.log"))
	logger.SetLogLevels("off")

	// Setup config
	xpub := "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFm" +
		"uMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx"
	cfg := &config.Config{
		DataDir: dataDir,
		TestNet: true,
		LegacyConfig: config.LegacyConfig{
			PaywallAmount:   1e7,
			PaywallXpub:     xpub,
			VoteDurationMin: 2016,
			VoteDurationMax: 4032,
			Mode:            config.CMSWWWMode,
		},
	}

	// Setup database
	db, err := localdb.New(filepath.Join(cfg.DataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	// Register cms userdb plugin
	plugin := user.Plugin{
		ID:      user.CMSPluginID,
		Version: user.CMSPluginVersion,
	}
	err = db.RegisterPlugin(plugin)
	if err != nil {
		t.Fatalf("register userdb plugin: %v", err)
	}

	// Setup smtp
	mailClient, err := mail.NewClient("", "", "", "", "", false, 0, db)
	if err != nil {
		t.Fatalf("setup SMTP: %v", err)
	}

	// Setup sessions
	cookieKey, err := util.Random(32)
	if err != nil {
		t.Fatalf("create cookie key: %v", err)
	}

	// Create politeiawww context
	p := Politeiawww{
		cfg:             cfg,
		db:              db,
		params:          chaincfg.TestNet3Params(),
		router:          mux.NewRouter(),
		auth:            mux.NewRouter(),
		sessions:        sessions.New(db, cookieKey),
		mail:            mailClient,
		test:            true,
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
	}

	// Setup routes
	p.setCMSWWWRoutes()
	p.setCMSUserWWWRoutes()

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

		/*
			err = logRotator.Close()
			if err != nil {
				t.Fatalf("close log rotator: %v", err)
			}
		*/

		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatalf("remove tmp dir: %v", err)
		}
	}
}
