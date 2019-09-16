// +build cockroachdb

// The tests in this file need cockroachdb to be up and will only be run if you
// specify "-tags=cockroachdb" with `go test`.

package cockroachdb

import (
	"os"
	"path"
	"testing"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func modelToSession(s Session) user.Session {
	return user.Session{
		ID:        s.ID,
		UserID:    s.UserID,
		MaxAge:    s.MaxAge,
		CreatedAt: s.CreatedAt.Unix(),
	}
}

var testDBConnection *cockroachdb

func connectToTestDB(t *testing.T) *cockroachdb {
	home := os.Getenv("HOME")
	var (
		tdbhost        string = "localhost:26257"
		tnetwork       string = "testnet3"
		tdbrootcert    string = path.Join(home, ".cockroachdb/certs/clients/politeiawww/ca.crt")
		tdbcert        string = path.Join(home, ".cockroachdb/certs/clients/politeiawww/client.politeiawww.crt")
		tdbkey         string = path.Join(home, ".cockroachdb/certs/clients/politeiawww/client.politeiawww.key")
		tencryptionkey string = path.Join(home, ".politeiawww/sbox.key")
		err            error
	)

	if testDBConnection == nil {
		testDBConnection, err = New(tdbhost, tnetwork, tdbrootcert, tdbcert, tdbkey, tencryptionkey)
		if err != nil {
			t.Fatalf("cockroachdb.New() returned an error: %v", err)
		}
	}
	return testDBConnection
}

func TestSessionNew(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
		MaxAge: 2,
	}
	var model Session

	err := db.SessionNew(expected)
	if err != nil {
		t.Errorf("SessionNew() returned an error: %v", err)
	}
	err = db.userDB.Where("id = ?", expected.ID).Last(&model).Error
	if err != nil {
		t.Errorf("Last() returned an error: %v", err)
	}
	expected.CreatedAt = model.CreatedAt.Unix()
	if expected != modelToSession(model) {
		t.Errorf("got session: %v, want: %v", model, expected)
	}
}

func TestSessionNewWithDefaultMaxAge(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
		// omit MaxAge, it should be set to default defined in gorm model (86400)
	}
	var model Session

	err := db.SessionNew(expected)
	if err != nil {
		t.Errorf("SessionNew() returned an error: %v", err)
	}
	err = db.userDB.Where("id = ?", expected.ID).Last(&model).Error
	if err != nil {
		t.Errorf("Last() returned an error: %v", err)
	}
	expected.CreatedAt = model.CreatedAt.Unix()
	expected.MaxAge = 86400
	if expected != modelToSession(model) {
		t.Errorf("got session: %v, want: %v", model, expected)
	}
}

func TestSessionNewSameID(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
		MaxAge: 3,
	}

	err := db.SessionNew(expected)
	if err != nil {
		t.Errorf("SessionNew() returned an error: %v", err)
	}
	// try inserting the same session
	err = db.SessionNew(expected)
	if err == nil {
		t.Error("SessionNew() did not return an error")
	}
	if err != user.ErrSessionExists {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionExists)
	}
}

func TestSessionGetById(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
		MaxAge: 4,
	}

	// insert a session
	err := db.SessionNew(expected)
	if err != nil {
		t.Errorf("SessionNew() returned an error: %v", err)
	}

	// get the Session we just inserted
	us, err := db.SessionGetById(expected.ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}

	// make sure the CreatedAt time stamp is correct
	var model Session
	err = db.userDB.Where("id = ?", expected.ID).First(&model).Error
	if err != nil {
		t.Errorf("First() returned an error: %v", err)
	}
	if us.CreatedAt != model.CreatedAt.Unix() {
		t.Errorf("got CreatedAt: %v, want: %v", us.CreatedAt, model.CreatedAt.Unix())
	}

	expected.CreatedAt = us.CreatedAt
	if expected != *us {
		t.Errorf("got session: %v, want: %v", us, expected)
	}
}

func TestSessionGetByIdWithNoRecord(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
		MaxAge: 5,
	}

	// try to get a session that does not exist
	_, err := db.SessionGetById(expected.ID)
	if err == nil {
		t.Error("SessionGetById() did not return an error")
	}
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
}

func TestSessionDeleteById(t *testing.T) {
	db := connectToTestDB(t)
	var err error
	sa := []user.Session{
		{
			ID:     uuid.New(),
			UserID: uuid.New(),
			MaxAge: 6,
		},
		{
			ID:     uuid.New(),
			UserID: uuid.New(),
			MaxAge: 7,
		},
		{
			ID:     uuid.New(),
			UserID: uuid.New(),
			MaxAge: 8,
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionNew(s)
		if err != nil {
			t.Errorf("idx: %v, SessionNew() returned an error: %v", idx, err)
		}
	}

	removed := []int{1}
	for _, idx := range removed {
		// delete the session
		err = db.SessionDeleteById(sa[idx].ID)
		if err != nil {
			t.Errorf("idx: %v, SessionDeleteById() returned an error: %v", idx, err)
		}
		// make sure the deleted session is gone
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err, gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx, sa[idx].ID, err)
		}
		sa[idx].CreatedAt = model.CreatedAt.Unix()
		if sa[idx] != modelToSession(model) {
			t.Errorf("got session: %v, want: %v", modelToSession(model), sa[idx])
		}
	}
}

func TestSessionDeleteByUserId(t *testing.T) {
	db := connectToTestDB(t)
	var err error
	keep := uuid.New()
	remove := uuid.New()

	sa := []user.Session{
		{
			ID:     uuid.New(),
			UserID: keep,
			MaxAge: 9,
		},
		{
			ID:     uuid.New(),
			UserID: remove,
			MaxAge: 10,
		},
		{
			ID:     uuid.New(),
			UserID: keep,
			MaxAge: 11,
		},
		{
			ID:     uuid.New(),
			UserID: remove,
			MaxAge: 12,
		},
		{
			ID:     uuid.New(),
			UserID: keep,
			MaxAge: 13,
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionNew(s)
		if err != nil {
			t.Errorf("idx: %v, SessionNew() returned an error: %v", idx, err)
		}
	}

	err = db.SessionsDeleteByUserId(remove, uuid.Nil)
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}

	removed := []int{1, 3}
	for _, idx := range removed {
		// make sure the deleted session is gone
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err, gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 4}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx, sa[idx].ID, err)
		}
		sa[idx].CreatedAt = model.CreatedAt.Unix()
		if sa[idx] != modelToSession(model) {
			t.Errorf("got session: %v, want: %v", modelToSession(model), sa[idx])
		}
	}
}

func TestSessionDeleteByUserIdAndSessionToKeep(t *testing.T) {
	db := connectToTestDB(t)
	var err error
	keep := uuid.New()
	remove := uuid.New()

	sa := []user.Session{
		{
			ID:     uuid.New(),
			UserID: keep,
			MaxAge: 14,
		},
		{
			ID:     uuid.New(),
			UserID: remove,
			MaxAge: 15,
		},
		{
			ID:     uuid.New(),
			UserID: keep,
			MaxAge: 16,
		},
		{
			ID:     uuid.New(),
			UserID: remove,
			MaxAge: 17,
		},
		{
			ID:     uuid.New(),
			UserID: remove,
			MaxAge: 18,
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionNew(s)
		if err != nil {
			t.Errorf("idx: %v, SessionNew() returned an error: %v", idx, err)
		}
	}

	// remove all sessions associated with user id `remove` except the one with
	// index 3
	err = db.SessionsDeleteByUserId(remove, sa[3].ID)
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}

	removed := []int{1, 4}
	for _, idx := range removed {
		// make sure the deleted session is gone
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err, gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 3}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx, sa[idx].ID, err)
		}
		sa[idx].CreatedAt = model.CreatedAt.Unix()
		if sa[idx] != modelToSession(model) {
			t.Errorf("got session: %v, want: %v", modelToSession(model), sa[idx])
		}
	}
}

func TestSessionDeleteByIdAndNoSession(t *testing.T) {
	db := connectToTestDB(t)
	err := db.SessionDeleteById(uuid.Nil)

	if err != nil {
		t.Errorf("SessionDeleteById() returned an error: %v", err)
	}
}
