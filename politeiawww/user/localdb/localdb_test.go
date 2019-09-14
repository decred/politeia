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

func TestSessionNew(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
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
	s.CreatedAt = sessionInDB.CreatedAt
	if s != *sessionInDB {
		t.Errorf("got session: %v, want: %v", sessionInDB, s)
	}
}

func TestSessionExistsAlready(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
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
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
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
	s.CreatedAt = sessionInDB.CreatedAt
	if s != *sessionInDB {
		t.Errorf("got session: %v, want: %v", sessionInDB, s)
	}
}

func TestSessionGetByIdAndNoRecord(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	_, err = db.SessionGetById(uuid.New())
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
}

func TestSessionDeleteById(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
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
			t.Errorf("SessionNew() returned an error for: %v", s)
		}
	}
	err = db.SessionDeleteById(sa[1].ID)
	if err != nil {
		t.Errorf("SessionDeleteById() returned an error: %v", err)
	}
	// make sure the right session got deleted
	sessionInDB, err := db.SessionGetById(sa[1].ID)
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
	// make sure the other 2 sessions are still in place
	kept := []int{0, 2}
	for _, idx := range kept {
		sessionInDB, err = db.SessionGetById(sa[idx].ID)
		if err != nil {
			t.Errorf("SessionGetById() returned an error: %v", err)
		}
		sa[idx].CreatedAt = sessionInDB.CreatedAt
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

func TestSessionsDeleteByUserId(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	remove := uuid.New()
	keep := uuid.New()
	sa := []user.Session{
		{ID: uuid.New(),
			UserID:    keep,
			CreatedAt: 5,
			MaxAge:    6},
		{ID: uuid.New(),
			UserID:    remove,
			CreatedAt: 7,
			MaxAge:    8},
		{ID: uuid.New(),
			UserID:    keep,
			CreatedAt: 9,
			MaxAge:    10},
		{ID: uuid.New(),
			UserID:    remove,
			CreatedAt: 11,
			MaxAge:    12},
		{ID: uuid.New(),
			UserID:    keep,
			CreatedAt: 13,
			MaxAge:    14},
	}
	for _, s := range sa {
		err = db.SessionNew(s)
		if err != nil {
			t.Errorf("SessionNew() returned an error for: %v", s)
		}
	}
	err = db.SessionsDeleteByUserId(remove, uuid.Nil)
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}
	// make sure the right session got deleted
	removed := []int{1, 3}
	for _, idx := range removed {
		_, err := db.SessionGetById(sa[idx].ID)
		if err != user.ErrSessionDoesNotExist {
			t.Errorf("index: %v, got error: %v, want: %v", idx, err, user.ErrSessionDoesNotExist)
		}
	}
	// make sure the other sessions are still in place
	kept := []int{0, 2, 4}
	for _, idx := range kept {
		sessionInDB, err := db.SessionGetById(sa[idx].ID)
		if err != nil {
			t.Errorf("index: %v, SessionGetById() returned an error: %v", idx, err)
		}
		sa[idx].CreatedAt = sessionInDB.CreatedAt
		if *sessionInDB != sa[idx] {
			t.Errorf("index: %v, got session: %v, want: %v", idx, sessionInDB, sa[idx])
		}
	}
}

func TestSessionsDeleteByUserIdAndKeepOneSession(t *testing.T) {
	var err error
	db, dataDir := setupTestData(t)
	defer teardownTestData(t, db, dataDir)
	remove := uuid.New()
	keep := uuid.New()
	sa := []user.Session{
		{ID: uuid.New(),
			UserID:    keep,
			CreatedAt: 5,
			MaxAge:    6},
		{ID: uuid.New(),
			UserID:    remove,
			CreatedAt: 7,
			MaxAge:    8},
		{ID: uuid.New(),
			UserID:    keep,
			CreatedAt: 9,
			MaxAge:    10},
		{ID: uuid.New(),
			UserID:    remove,
			CreatedAt: 11,
			MaxAge:    12},
		{ID: uuid.New(),
			UserID:    remove,
			CreatedAt: 13,
			MaxAge:    14},
	}
	for _, s := range sa {
		err = db.SessionNew(s)
		if err != nil {
			t.Errorf("SessionNew() returned an error for: %v", s)
		}
	}
	// delete all sessions associated with the `removed` user id
	// except the one with index 3.
	err = db.SessionsDeleteByUserId(remove, sa[3].ID)
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}
	// make sure the right sessions got deleted
	removed := []int{1, 4}
	for _, idx := range removed {
		_, err := db.SessionGetById(sa[idx].ID)
		if err != user.ErrSessionDoesNotExist {
			t.Errorf("index: %v, got error: %v, want: %v", idx, err, user.ErrSessionDoesNotExist)
		}
	}
	// make sure the other sessions are still in place
	kept := []int{0, 2, 3}
	for _, idx := range kept {
		sessionInDB, err := db.SessionGetById(sa[idx].ID)
		if err != nil {
			t.Errorf("index: %v, SessionGetById() returned an error: %v", idx, err)
		}
		sa[idx].CreatedAt = sessionInDB.CreatedAt
		if *sessionInDB != sa[idx] {
			t.Errorf("index: %v, got session: %v, want: %v", idx, sessionInDB, sa[idx])
		}
	}
}
