// +build cockroachdb

// The tests in this file need cockroachdb to be up and will only be run if you
// specify "-tags=cockroachdb" with `go test`.

package cockroachdb

import (
	stdlog "log"
	"os"
	"strings"
	"testing"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	flags "github.com/jessevdk/go-flags"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var testDB *cockroachdb

func modelToSession(s Session) user.Session {
	return user.Session{
		ID:     s.ID,
		UserID: s.UserID,
		Values: s.Values,
	}
}

func expandTilde(s string) string {
	if strings.HasPrefix(s, "~/") {
		home := os.Getenv("HOME")
		return strings.Replace(s, "~", home, 1)
	}
	return s
}

func connectToTestDB() *cockroachdb {
	if testDB != nil {
		// db already initialized
		return testDB
	}

	type config struct {
		DBHost        string `long:"dbhost" description:"Database ip:port"`
		DBRootCert    string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
		DBCert        string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
		DBKey         string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
		Network       string `long:"network" description:"The name of the network to use"`
		EncryptionKey string `long:"encryptionkey" description:"The encryptionkey key to use"`
	}
	cfg := config{}
	parser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(parser).ParseFile("testdata/test.conf")
	if err != nil {
		stdlog.Fatalf("ParseFile() failed, %v", err)
	}
	cfg.DBRootCert = expandTilde(cfg.DBRootCert)
	cfg.DBCert = expandTilde(cfg.DBCert)
	cfg.DBKey = expandTilde(cfg.DBKey)
	cfg.EncryptionKey = expandTilde(cfg.EncryptionKey)

	testDB, err = New(cfg.DBHost, cfg.Network, cfg.DBRootCert,
		cfg.DBCert, cfg.DBKey, cfg.EncryptionKey)
	if err != nil {
		stdlog.Fatalf("cockroachdb.New() returned an error: %v", err)
	}
	return testDB
}

func TestMain(m *testing.M) {
	connectToTestDB()
	exitVal := m.Run()
	testDB.Close()

	os.Exit(exitVal)
}

func TestSessionSave(t *testing.T) {
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionSave()",
	}
	var model Session

	err := testDB.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() returned an error: %v", err)
	}
	err = testDB.userDB.Where("id = ?", expected.ID).Last(&model).Error
	if err != nil {
		t.Errorf("Last() returned an error: %v", err)
	}
	if expected != modelToSession(model) {
		t.Errorf("got session: %v, want: %v", model, expected)
	}
}

func TestSessionSaveMoreThanOnce(t *testing.T) {
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionSaveMoreThanOnce()",
	}

	err := testDB.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() #1 returned an error: %v", err)
	}
	// try updating the same session, this should not return an error but
	// update the record.
	expected.Values += " / update"
	expected.UserID = uuid.New()
	err = testDB.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() #2 returned an error: %v", err)
	}

	us2, err := testDB.SessionGetById(expected.ID)
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
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionDeleteById()",
	}

	// insert a session
	err := testDB.SessionSave(expected)
	if err != nil {
		t.Errorf("SessionSave() returned an error: %v", err)
	}

	// get the Session we just inserted
	us, err := testDB.SessionGetById(expected.ID)
	if err != nil {
		t.Errorf("SessionGetById() returned an error: %v", err)
	}

	var model Session
	err = testDB.userDB.Where("id = ?", expected.ID).First(&model).Error
	if err != nil {
		t.Errorf("First() returned an error: %v", err)
	}

	if expected != *us {
		t.Errorf("got session: %v, want: %v", us, expected)
	}
}

func TestSessionGetByIdWithNoRecord(t *testing.T) {
	expected := user.Session{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		Values: "TestSessionGetByIdWithNoRecord()",
	}

	// try to get a session that does not exist
	_, err := testDB.SessionGetById(expected.ID)
	if err == nil {
		t.Error("SessionGetById() did not return an error")
	}
	if err != user.ErrSessionDoesNotExist {
		t.Errorf("got error: %v, want: %v", err, user.ErrSessionDoesNotExist)
	}
}

func TestSessionDeleteById(t *testing.T) {
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
		err = testDB.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
		}
	}

	removed := []int{1}
	for _, idx := range removed {
		// delete the session
		err = testDB.SessionDeleteById(sa[idx].ID)
		if err != nil {
			t.Errorf("idx: %v, SessionDeleteById() error: %v", idx, err)
		}
		// make sure the deleted session is gone
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2}
	for _, idx := range kept {
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
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
		err = testDB.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
		}
	}

	err = testDB.SessionsDeleteByUserId(remove, "")
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}

	removed := []int{1, 3}
	for _, idx := range removed {
		// make sure the deleted session is gone
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 4}
	for _, idx := range kept {
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
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
		err = testDB.SessionSave(s)
		if err != nil {
			t.Errorf("idx: %v, SessionSave() returned an error: %v", idx, err)
		}
	}

	// remove all sessions associated with user id `remove` except the one with
	// index 3
	err = testDB.SessionsDeleteByUserId(remove, sa[3].ID)
	if err != nil {
		t.Errorf("SessionsDeleteByUserId() returned an error: %v", err)
	}

	removed := []int{1, 4}
	for _, idx := range removed {
		// make sure the deleted session is gone
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
		if err != gorm.ErrRecordNotFound {
			t.Errorf("idx: %v, got error: %v, want: %v", idx, err,
				gorm.ErrRecordNotFound)
		}
	}
	// make sure the other sessions are stil in place
	kept := []int{0, 2, 3}
	for _, idx := range kept {
		var model Session
		err = testDB.userDB.Where("id = ?", sa[idx].ID).First(&model).Error
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
	err := testDB.SessionDeleteById(uuid.Nil.String())

	if err != nil {
		t.Errorf("SessionDeleteById() returned an error: %v", err)
	}
}
