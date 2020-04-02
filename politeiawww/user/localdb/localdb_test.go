// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"encoding/base32"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
)

func setupTestData(t *testing.T) (*localdb, string) {
	t.Helper()

	dataDir, err := ioutil.TempDir("", "politeiawww.user.localdb.test")
	if err != nil {
		t.Fatalf("tmp dir: %v", err)
	}

	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}

	return db, dataDir
}

func teardownTestData(t *testing.T, db *localdb, dataDir string) {
	t.Helper()

	err := db.Close()
	if err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = os.RemoveAll(dataDir)
	if err != nil {
		t.Fatalf("remove tmp dir: %v", err)
	}
}

func newSessionID() string {
	return base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
}

func TestSessionSave(t *testing.T) {
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)

	// Save session
	s := user.Session{
		ID:     newSessionID(),
		UserID: uuid.New(),
		Values: "v1",
	}
	err := db.SessionSave(s)
	if err != nil {
		t.Error(err)
	}

	// Verify session
	b, err := db.userdb.Get([]byte(sessionPrefix+s.ID), nil)
	if err != nil {
		t.Error(err)
	}
	sessionInDB, err := user.DecodeSession(b)
	if err != nil {
		t.Error(err)
	}
	if *sessionInDB != s {
		t.Errorf("got session %v, want %v", sessionInDB, s)
	}

	// Save a session that already exists
	s.Values = "v2"
	err = db.SessionSave(s)
	if err != nil {
		t.Error(err)
	}

	// Verify session was updated correctly
	b, err = db.userdb.Get([]byte(sessionPrefix+s.ID), nil)
	if err != nil {
		t.Error(err)
	}
	sessionInDB, err = user.DecodeSession(b)
	if err != nil {
		t.Error(err)
	}
	if *sessionInDB != s {
		t.Errorf("got session %v, want %v", sessionInDB, s)
	}
}

func TestSessionGetByID(t *testing.T) {
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)

	// Save session
	s := user.Session{
		ID:     newSessionID(),
		UserID: uuid.New(),
		Values: "",
	}
	err := db.SessionSave(s)
	if err != nil {
		t.Error(err)
	}

	// Get existing session
	sessionInDB, err := db.SessionGetByID(s.ID)
	if err != nil {
		t.Error(err)
	}
	if *sessionInDB != s {
		t.Errorf("got session %v, want %v", sessionInDB, s)
	}

	// Get session that does not exist
	_, err = db.SessionGetByID(uuid.New().String())
	if err != user.ErrSessionNotFound {
		t.Errorf("got error '%v', want '%v'", err, user.ErrSessionNotFound)
	}
}

func TestSessionDeleteByID(t *testing.T) {
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)

	// Session 1
	s1 := user.Session{
		ID:     newSessionID(),
		UserID: uuid.New(),
		Values: "",
	}

	// Session 2
	s2 := user.Session{
		ID:     newSessionID(),
		UserID: uuid.New(),
		Values: "",
	}

	// Save sessions
	err := db.SessionSave(s1)
	if err != nil {
		t.Fatal(err)
	}
	err = db.SessionSave(s2)
	if err != nil {
		t.Fatal(err)
	}

	// Delete one of the sessions
	err = db.SessionDeleteByID(s1.ID)
	if err != nil {
		t.Error(err)
	}

	// Verify session was deleted
	_, err = db.SessionGetByID(s1.ID)
	if err != user.ErrSessionNotFound {
		t.Errorf("error got '%v', want '%v'", err, user.ErrSessionNotFound)
	}

	// Verify the remaining session still exists
	s2DB, err := db.SessionGetByID(s2.ID)
	if err != nil {
		t.Errorf("error got '%v', want nil", err)
	}
	if *s2DB != s2 {
		t.Errorf("session got %v, want %v", s2DB, s2)
	}
}

func TestIsUserRecord(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{
			input: UserVersionKey,
			want:  false,
		},
		{
			input: LastPaywallAddressIndex,
			want:  false,
		},
		{
			input: sessionPrefix + uuid.New().String(),
			want:  false,
		},
	}

	for _, test := range tests {
		got := isUserRecord(test.input)
		if got != test.want {
			t.Errorf("isUserRecord(%v) got %v, want %v",
				test.input, got, test.want)
		}
	}
}
