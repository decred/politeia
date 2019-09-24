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
		ID:     s.ID,
		UserID: s.UserID,
		Values: s.Values,
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
		testDBConnection, err = New(tdbhost, tnetwork, tdbrootcert, tdbcert,
			tdbkey, tencryptionkey)
		if err != nil {
			t.Fatalf("cockroachdb.New() returned an error: %v", err)
		}
	}
	return testDBConnection
}

func TestSessionSave(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionSave()",
	}
	var model Session

	err := db.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() returned an error: %v", err)
	}
	err = db.userDB.Where("id = ?", expected.ID).Last(&model).Error
	if err != nil {
		t.Errorf("Last() returned an error: %v", err)
	}
	if expected != modelToSession(model) {
		t.Errorf("got session: %v, want: %v", model, expected)
	}
}

func TestSessionSaveMoreThanOnce(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionSaveMoreThanOnce()",
	}

	err := db.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() #1 returned an error: %v", err)
	}
	// try updating the same session, this should not return an error but
	// update the record.
	expected.Values += " / update"
	expected.UserID = uuid.New()
	err = db.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() #2 returned an error: %v", err)
	}

	us2, err := db.SessionGetById(expected.ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}

	if us2.Values != expected.Values {
		t.Errorf("got Values: %v, want: %v", us2.Values, expected.Values)
	}
	if us2.UserID != expected.UserID {
		t.Errorf("got UserID: %v, want: %v", us2.UserID, expected.UserID)
	}
}

func TestSessionGetById(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionDeleteById()",
	}

	// insert a session
	err := db.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() returned an error: %v", err)
	}

	// get the Session we just inserted
	us, err := db.SessionGetById(expected.ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}

	var model Session
	err = db.userDB.Where("id = ?", expected.ID).First(&model).Error
	if err != nil {
		t.Errorf("First() returned an error: %v", err)
	}

	if expected != *us {
		t.Errorf("got session: %v, want: %v", us, expected)
	}
}

func TestSessionGetByIdWithNoRecord(t *testing.T) {
	db := connectToTestDB(t)
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionGetByIdWithNoRecord()",
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
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteById() / 1",
		},
		{
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteById() / 2",
		},
		{
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			Values: "TestSessionDeleteById() / 3",
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
		}
	}

	removed := []int{1}
	for _, idx := range removed {
		// delete the session
		err = db.SessionDeleteById(sa[idx].ID)
		if err != nil {
			t.Errorf("idx: %v, SessionDeleteById() error: %v", idx, err)
		}
		// make sure the deleted session is gone
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx,
				sa[idx].ID, err)
		}
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
			ID:     uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserId() / 9",
		},
		{
			ID:     uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserId() /10",
		},
		{
			ID:     uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserId() /11",
		},
		{
			ID:     uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserId() /12",
		},
		{
			ID:     uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserId() /13",
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
		}
	}

	err = db.SessionsDeleteByUserId(remove, "")
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}

	removed := []int{1, 3}
	for _, idx := range removed {
		// make sure the deleted session is gone
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 4}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx,
				sa[idx].ID, err)
		}
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
			ID:     uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserId() /14",
		},
		{
			ID:     uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserId() /15",
		},
		{
			ID:     uuid.New().String(),
			UserID: keep,
			Values: "TestSessionDeleteByUserId() /16",
		},
		{
			ID:     uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserId() /17",
		},
		{
			ID:     uuid.New().String(),
			UserID: remove,
			Values: "TestSessionDeleteByUserId() /18",
		},
	}

	for idx, s := range sa {
		// insert a session
		err = db.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
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
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 3}
	for _, idx := range kept {
		var model Session
		err = db.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != nil {
			t.Errorf("idx: %v (%v), First() returned an error: %v", idx,
				sa[idx].ID, err)
		}
		if sa[idx] != modelToSession(model) {
			t.Errorf("got session: %v, want: %v", modelToSession(model), sa[idx])
		}
	}
}

func TestSessionDeleteByIdAndNoSession(t *testing.T) {
	db := connectToTestDB(t)
	err := db.SessionDeleteById(uuid.Nil.String())

	if err != nil {
		t.Errorf("SessionDeleteById() returned an error: %v", err)
	}
}
