package localdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func setupTestData(t *testing.T) (*localdb, string) {
	// Setup database
	dataDir, err := ioutil.TempDir("", "politeiawww.user.localdb.test")
	if err != nil {
		t.Error("TempDir() returned an error")
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

func TestSessionSave(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	s := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionSave()",
	}
	err = db.SessionSave(s)
	if err != nil {
		t.Error("SessionSave() returned an error")
	}
	data, err := db.userdb.Get([]byte(sessionPrefix+s.ID), nil)
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
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	s := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionExistsAlready()",
	}
	err = db.SessionSave(s)
	if err != nil {
		t.Error("SessionSave() #1 returned an error")
	}
	// repeated insertion should not result in an error but just update
	// the record.
	s.Values += " -- version 2"
	err = db.SessionSave(s)
	if err != nil {
		t.Error("SessionSave() #2 returned an error")
	}
	us2, err := db.SessionGetByID(s.ID)
	if err != nil {
		t.Error("SessionGetByID() returned an error")
	}
	if s.Values != us2.Values {
		t.Errorf("got Values: %v, want: %v", us2.Values, s.Values)
	}
}

func TestSessionGetByID(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	s := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionGetByID()",
	}
	err = db.SessionSave(s)
	if err != nil {
		t.Error("SessionSave() returned an error")
	}
	sessionInDB, err := db.SessionGetByID(s.ID)
	if err != nil {
		t.Errorf("SessionGetByID() returned an error: %v", err)
	}
	if sessionInDB == nil {
		t.Error("SessionGetByID() returned a nil pointer")
	}
	if s != *sessionInDB {
		t.Errorf("got session: %v, want: %v", sessionInDB, s)
	}
}

func TestSessionGetByIDAndNoRecord(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	_, err = db.SessionGetByID(uuid.New().String())
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
}

func TestSessionDeleteByID(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	sa := []user.Session{
		{ID: uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteByID() / 1"},
		{ID: uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteByID() / 2"},
		{ID: uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteByID() / 3"},
	}
	for _, s := range sa {
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("SessionSave() returned an error for: %v", s)
		}
	}
	err = db.SessionDeleteByID(sa[1].ID)
	if err != nil {
		t.Errorf("SessionDeleteByID() returned an error: %v", err)
	}
	// make sure the right session got deleted
	_, err = db.SessionGetByID(sa[1].ID)
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
	// make sure the other 2 sessions are still in place
	kept := []int{0, 2}
	for _, idx := range kept {
		sessionInDB, err := db.SessionGetByID(sa[idx].ID)
		if err != nil {
			t.Errorf("SessionGetByID() returned an error: %v", err)
		}
		if *sessionInDB != sa[idx] {
			t.Errorf("got session: %v, want: %v", sessionInDB, sa[idx])
		}
	}
}

func TestIsUserRecordWithSessionKey(t *testing.T) {
	result := isUserRecord(sessionPrefix + uuid.New().String())
	if result != false {
		t.Error("isUserRecord() confuses User and Session records")
	}
}

func TestSessionsDeleteByUserID(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	remove := uuid.New()
	keep := uuid.New()
	sa := []user.Session{
		{ID: uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserID() / 1"},
		{ID: uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserID() / 2"},
		{ID: uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserID() / 3"},
		{ID: uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserID() / 5"},
		{ID: uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserID() / 5"},
	}
	for _, s := range sa {
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("SessionSave() returned an error for: %v", s)
		}
	}
	err = db.SessionsDeleteByUserID(remove, "")
	if err != nil {
		t.Errorf("SessionsDeleteByUserID() returned an error: %v", err)
	}
	// make sure the right session got deleted
	removed := []int{1, 3}
	for _, idx := range removed {
		_, err := db.SessionGetByID(sa[idx].ID)
		if err != user.ErrSessionDoesNotExist {
			t.Errorf("index: %v, got error: %v, want: %v", idx, err,
				user.ErrSessionDoesNotExist)
		}
	}
	// make sure the other sessions are still in place
	kept := []int{0, 2, 4}
	for _, idx := range kept {
		sessionInDB, err := db.SessionGetByID(sa[idx].ID)
		if err != nil {
			t.Errorf("index: %v, SessionGetByID() returned an error: %v", idx, err)
		}
		if *sessionInDB != sa[idx] {
			t.Errorf("index: %v, got session: %v, want: %v", idx, sessionInDB,
				sa[idx])
		}
	}
}

func TestSessionsDeleteByUserIDAndKeepOneSession(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	remove := uuid.New()
	keep := uuid.New()
	sa := []user.Session{
		{ID: uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserID() / 6"},
		{ID: uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserID() / 7"},
		{ID: uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserID() / 8"},
		{ID: uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserID() / 9"},
		{ID: uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserID() /10"},
	}
	for _, s := range sa {
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("SessionSave() returned an error for: %v", s)
		}
	}
	// delete all sessions associated with the `removed` user id
	// except the one with index 3.
	err = db.SessionsDeleteByUserID(remove, sa[3].ID)
	if err != nil {
		t.Errorf("SessionsDeleteByUserID() returned an error: %v", err)
	}
	// make sure the right sessions got deleted
	removed := []int{1, 4}
	for _, idx := range removed {
		_, err := db.SessionGetByID(sa[idx].ID)
		if err != user.ErrSessionDoesNotExist {
			t.Errorf("index: %v, got error: %v, want: %v", idx, err,
				user.ErrSessionDoesNotExist)
		}
	}
	// make sure the other sessions are still in place
	kept := []int{0, 2, 3}
	for _, idx := range kept {
		sessionInDB, err := db.SessionGetByID(sa[idx].ID)
		if err != nil {
			t.Errorf("index: %v, SessionGetByID() returned an error: %v", idx, err)
		}
		if *sessionInDB != sa[idx] {
			t.Errorf("index: %v, got session: %v, want: %v", idx, sessionInDB,
				sa[idx])
		}
	}
}

func TestSessionDeleteByIDAndNoSession(t *testing.T) {
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	err := db.SessionDeleteByID(uuid.Nil.String())
	if err != nil {
		t.Errorf("SessionDeleteByID() returned an error: %v", err)
	}
}
