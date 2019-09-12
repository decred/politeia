package localdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func cleanup(t *testing.T, db *localdb, dataDir string) {
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

func TestSessionNew(t *testing.T) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}
	defer cleanup(t, db, dataDir)
	s := user.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: 1,
		MaxAge:    2,
	}
	err = db.SessionNew(s)
	if err != nil {
		t.Error("SessionNew() returned an error")
	}
	data, err := db.userdb.Get([]byte(sessionPrefix+s.ID.String()), nil)
	if err != nil {
		t.Errorf("db.Get() returned an error: %v", err)
	}
	sessionInDB, err := user.DecodeSession(data)
	if err != nil {
		t.Errorf("DecodeSession() returned an error: %v", err)
	}
	if sessionInDB == nil {
		t.Error("DecodeSession() returned a nil pointer")
	}
	if s != *sessionInDB {
		t.Errorf("got session: %v, want: %v", sessionInDB, s)
	}
}

func TestSessionExistsAlready(t *testing.T) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}
	defer cleanup(t, db, dataDir)
	s := user.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: 1,
		MaxAge:    2,
	}
	err = db.SessionNew(s)
	if err != nil {
		t.Error("SessionNew() returned an error")
	}
	// repeated insertion should result in an error
	err = db.SessionNew(s)
	if err != user.ErrSessionExists {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionExists)
	}
}

func TestSessionGetById(t *testing.T) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}
	defer cleanup(t, db, dataDir)
	s := user.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: 3,
		MaxAge:    4,
	}
	err = db.SessionNew(s)
	if err != nil {
		t.Error("SessionNew() returned an error")
	}
	sessionInDB, err := db.SessionGetById(s.ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}
	if sessionInDB == nil {
		t.Error("SessionGetById() returned a nil pointer")
	}
	if s != *sessionInDB {
		t.Errorf("got session: %v, want: %v", sessionInDB, s)
	}
}

func TestSessionGetByIdAndNoRecord(t *testing.T) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}
	defer cleanup(t, db, dataDir)
	s := user.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: 3,
		MaxAge:    4,
	}
	_, err = db.SessionGetById(s.ID)
	if err != user.ErrSessionNotFound {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionNotFound)
	}
}

func TestSessionDeleteById(t *testing.T) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.test")
	db, err := New(filepath.Join(dataDir, "localdb"))
	if err != nil {
		t.Fatalf("setup database: %v", err)
	}
	defer cleanup(t, db, dataDir)
	sa := []user.Session{
		{ID: uuid.New(),
			UserID:    uuid.New(),
			CreatedAt: 5,
			MaxAge:    6},
		{ID: uuid.New(),
			UserID:    uuid.New(),
			CreatedAt: 7,
			MaxAge:    8},
		{ID: uuid.New(),
			UserID:    uuid.New(),
			CreatedAt: 9,
			MaxAge:    10},
	}
	for _, s := range sa {
		err = db.SessionNew(s)
		if err != nil {
			t.Error("SessionNew() returned an error")
		}
	}
	err = db.SessionDeleteById(sa[1].ID)
	if err != nil {
		t.Errorf("SessionDeleteById() returned an error: %v", err)
	}
	// make sure the right session got deleted
	sessionInDB, err := db.SessionGetById(sa[1].ID)
	if err != user.ErrSessionNotFound {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionNotFound)
	}
	// make sure the other 2 sessions are still in place
	sessionInDB, err = db.SessionGetById(sa[0].ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}
	if *sessionInDB != sa[0] {
		t.Errorf("got session: %v, want: %v", sessionInDB, sa[0])
	}
	sessionInDB, err = db.SessionGetById(sa[2].ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}
	if *sessionInDB != sa[2] {
		t.Errorf("got session: %v, want: %v", sessionInDB, sa[2])
	}
}
