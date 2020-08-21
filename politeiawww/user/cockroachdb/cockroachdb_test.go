package cockroachdb

import (
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/lib/pq"
)

// Custom go-sqlmock types for type assertion
type AnyBlob struct{}
type AnyTime struct{}

func (a AnyBlob) Match(v driver.Value) bool {
	_, ok := v.([]byte)
	return ok
}

func (a AnyTime) Match(v driver.Value) bool {
	_, ok := v.(time.Time)
	return ok
}

// Helpers
func newPaywallAddressIndex(t *testing.T, i uint64) *[]byte {
	t.Helper()

	index := make([]byte, 8)
	binary.LittleEndian.PutUint64(index, i)
	return &index
}

func newCdbUser(t *testing.T, cdb *cockroachdb) (User, []byte) {
	t.Helper()

	uuid := uuid.New()
	u := user.User{
		ID:       uuid,
		Username: "test" + uuid.String(),
	}

	// Make user identity
	fid, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	id, err := user.NewIdentity(hex.EncodeToString(fid.Public.Key[:]))
	if err != nil {
		t.Fatalf("%v", err)
	}
	u.Identities = append(u.Identities, *id)

	// Make user blob
	eu, err := user.EncodeUser(u)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := cdb.encrypt(user.VersionUser, eu)
	if err != nil {
		t.Fatalf("%s", err)
	}

	return convertUserFromUser(u, eb), eb
}

func setupTestDB(t *testing.T) (*cockroachdb, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error %s while creating stub db conn", err)
	}

	gdb, err := gorm.Open("postgres", db)
	if err != nil {
		t.Fatalf("error %s while opening db with gorm", err)
	}

	b := []byte("random")
	var key [32]byte
	copy(key[:], b)

	c := &cockroachdb{
		userDB:        gdb,
		encryptionKey: &key,
	}

	return c, mock, func() {
		db.Close()
	}
}

// Tests
func TestSetPaywallAddressIndex(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	i := uint64(1)
	index := newPaywallAddressIndex(t, i)

	// Query
	sql := `UPDATE "key_value" SET "value" = $1 WHERE "key_value"."key" = $2`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(index, keyPaywallAddressIndex).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method to match queries
	err := cdb.SetPaywallAddressIndex(i)
	if err != nil {
		t.Errorf("error creating new user %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserNewSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	index := newPaywallAddressIndex(t, 1)
	usr := user.User{
		Email:    "test@test.com",
		Username: "test",
	}

	// Queries
	sqlSelectIndex := `SELECT * FROM "key_value" WHERE "key_value"."key" = $1`

	sqlInsertUser := `INSERT INTO "users" ("id","username","blob","created_at","updated_at") VALUES ($1,$2,$3,$4,$5) RETURNING "users"."id"`

	sqlUpdateIndex := `UPDATE "key_value" SET "value" = $1 WHERE "key_value"."key" = $2`

	// Expectations
	mock.ExpectBegin()

	// Select paywall address index
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value"}).
			AddRow(keyPaywallAddressIndex, index))

	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{}, AnyTime{}, AnyTime{}).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(usr.ID))

	// Update paywall address index
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateIndex)).
		WithArgs(sqlmock.AnyArg(), keyPaywallAddressIndex).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	// Execute method to match queries
	err := cdb.UserNew(usr)
	if err != nil {
		t.Errorf("user new error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserNewFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	usr := user.User{
		Email:    "test@test.com",
		Username: "test",
	}

	// Query
	sql := `SELECT * FROM "key_value" WHERE "key_value"."key" = $1`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnError(fmt.Errorf("select paywall index error"))
	mock.ExpectRollback()

	// Execute method and expect error
	err := cdb.UserNew(usr)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserUpdateSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	uuid := uuid.New()
	usr := user.User{
		ID:         uuid,
		Identities: []user.Identity{},
		Email:      "test@test.com",
		Username:   "test",
	}

	// Query
	sql := `UPDATE "users" SET "username" = $1, "blob" = $2, "created_at" = $3, "updated_at" = $4  WHERE "users"."id" = $5`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username, AnyBlob{}, AnyTime{}, AnyTime{}, usr.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method to match queries
	err := cdb.UserUpdate(usr)
	if err != nil {
		t.Errorf("user update error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserUpdateFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	uuid := uuid.New()
	usr := user.User{
		ID:         uuid,
		Identities: []user.Identity{},
		Email:      "test@test.com",
		Username:   "test",
	}

	// Query
	sql := `UPDATE "users" SET "username" = $1, "blob" = $2, "created_at" = $3, "updated_at" = $4  WHERE "users"."id" = $5`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username, AnyBlob{}, AnyTime{}, AnyTime{}, usr.ID).
		WillReturnError(fmt.Errorf("update user error"))
	mock.ExpectRollback()

	// Execute method to match queries
	err := cdb.UserUpdate(usr)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByUsernameSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).AddRow(usr.ID, usr.Username, blob, now, now)

	// Query
	sql := `SELECT * FROM "users" WHERE (username = $1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username).
		WillReturnRows(rows)

	// Execute method to match queries
	u, err := cdb.UserGetByUsername(usr.Username)
	if err != nil {
		t.Errorf("user get by username error: %s", err)
	}

	// Make sure correct user was fetched
	if u.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, u.ID)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByUsernameFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Query
	sql := `SELECT * FROM "users" WHERE (username = $1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs("random").
		WillReturnError(user.ErrUserNotFound)

	// Execute method to match queries
	_, err := cdb.UserGetByUsername("random")
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByIdSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).AddRow(usr.ID, usr.Username, blob, now, now)

	// Query
	sql := `SELECT * FROM "users" WHERE (id = $1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.ID).
		WillReturnRows(rows)

	// Execute method to match queries
	u, err := cdb.UserGetById(usr.ID)
	if err != nil {
		t.Errorf("user get by id error: %s", err)
	}

	// Make sure correct user was fetched
	if u.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, u.ID)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByIdFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	uuid := uuid.New()

	// Query
	sql := `SELECT * FROM "users" WHERE (id = $1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(uuid).
		WillReturnError(user.ErrUserNotFound)

	// Execute method to match queries
	_, err := cdb.UserGetById(uuid)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByPubKeySuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)
	pubkey := usr.Identities[0].PublicKey

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).AddRow(usr.ID, usr.Username, blob, now, now)

	// Query
	sql := `SELECT * FROM users INNER JOIN identities ON users.id = identities.user_id WHERE identities.public_key = $1`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method to match queries
	ur, err := cdb.UserGetByPubKey(pubkey)
	if err != nil {
		t.Errorf("user get by pubkey error: %s", err)
	}

	// Make sure correct user was fetched
	if ur.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, ur.ID)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByPubKeyFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	fid, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubkey := hex.EncodeToString(fid.Public.Key[:])

	// Query
	sql := `SELECT * FROM users INNER JOIN identities ON users.id = identities.user_id WHERE identities.public_key = $1`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnError(user.ErrUserNotFound)

	// Execute method to match queries
	_, err = cdb.UserGetByPubKey(pubkey)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUsersGetByPubKeySuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)
	pubkey := usr.Identities[0].PublicKey

	// Mock data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).AddRow(usr.ID, usr.Username, blob, now, now)

	// Query
	sql := `SELECT * FROM users INNER JOIN identities ON users.id = identities.user_id WHERE identities.public_key IN ($1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method to match queries
	ur, err := cdb.UsersGetByPubKey([]string{pubkey})
	if err != nil {
		t.Errorf("users get by pubkey: %s", err)
	}

	// Make sure correct user was fetched
	fetchedUser := ur[pubkey]
	if fetchedUser.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, fetchedUser.ID)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUsersGetByPubKeyFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	fid, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubkey := hex.EncodeToString(fid.Public.Key[:])

	// Query
	sql := `SELECT * FROM users INNER JOIN identities ON users.id = identities.user_id WHERE identities.public_key IN ($1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnError(user.ErrUserNotFound)

	// Execute method to match queries
	_, err = cdb.UsersGetByPubKey([]string{pubkey})
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestAllUsersSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)
	usr2, blob2 := newCdbUser(t, cdb)

	// Mock data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).
		AddRow(usr.ID, usr.Username, blob, now, now).
		AddRow(usr2.ID, usr2.Username, blob2, now, now)

	// Query
	sql := `SELECT * FROM "users"`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnRows(rows)

	// Execute method to match queries
	var users []user.User
	err := cdb.AllUsers(func(u *user.User) {
		users = append(users, *u)
	})
	if err != nil {
		t.Errorf("all users error: %s", err)
	}

	// Check if both mocked users were returned
	if len(users) != 2 {
		t.Errorf("did not return all users")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestAllUsersFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Query
	sql := `SELECT * FROM "users"`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnError(fmt.Errorf("select all users error"))

	// Execute method to match queries
	var users []user.User
	err := cdb.AllUsers(func(u *user.User) {
		users = append(users, *u)
	})
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionSaveCreateSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sessionKey := hex.EncodeToString(util.Digest([]byte(session.ID)))

	// Query
	sqlSelect := `SELECT * FROM "sessions"  WHERE (key = $1)`

	sqlInsert := `INSERT INTO "sessions" ("key","user_id","created_at","blob") VALUES ($1,$2,$3,$4) RETURNING "sessions"."key"`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnRows(sqlmock.NewRows([]string{}))

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsert)).
		WithArgs(sessionKey, session.UserID, session.CreatedAt, AnyBlob{}).
		WillReturnRows(sqlmock.NewRows([]string{"key"}).AddRow(sessionKey))
	mock.ExpectCommit()

	// Execute method to match queries
	err := cdb.SessionSave(session)
	if err != nil {
		t.Errorf("session save error: %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionSaveUpdateSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sessionKey := hex.EncodeToString(util.Digest([]byte(session.ID)))

	// Mock data
	rows := sqlmock.NewRows([]string{"key", "user_id", "created_at", "blob"}).
		AddRow(sessionKey, session.UserID, session.CreatedAt, []byte{})

	// Queries
	sqlSelect := `SELECT * FROM "sessions"  WHERE (key = $1)`

	sqlUpdate := `UPDATE "sessions" SET "user_id" = $1, "created_at" = $2, "blob" = $3  WHERE "sessions"."key" = $4`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnRows(rows)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(session.UserID, session.CreatedAt, AnyBlob{}, sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method to match queries
	err := cdb.SessionSave(session)
	if err != nil {
		t.Errorf("session save error: %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionSaveFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Query
	sql := `SELECT * FROM "sessions"  WHERE (key = $1)`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnError(fmt.Errorf("select sessions error"))

	// Execute method to match queries
	err := cdb.SessionSave(user.Session{})
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionGetByIDSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sessionKey := hex.EncodeToString(util.Digest([]byte(session.ID)))
	sb, err := user.EncodeSession(session)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := cdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	rows := sqlmock.NewRows([]string{"key", "user_id", "created_at", "blob"}).
		AddRow(sessionKey, session.UserID, session.CreatedAt, eb)

	// Queries
	sql := `SELECT * FROM "sessions" WHERE "sessions"."key" = $1`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnRows(rows)

	// Execute method to match queries
	s, err := cdb.SessionGetByID(session.ID)
	if err != nil {
		t.Errorf("session get by id error: %s", err)
	}

	// Make sure correct session was returned
	if session.ID != s.ID {
		t.Errorf("expecting session %s but got %s", session.ID, s.ID)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionGetByIDFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	sessionKey := hex.EncodeToString(util.Digest([]byte("random")))

	// Query
	sql := `SELECT * FROM "sessions" WHERE "sessions"."key" = $1`

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnError(fmt.Errorf("select sessions error"))

	// Execute method to match queries
	_, err := cdb.SessionGetByID(sessionKey)
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionDeleteByIDSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sessionKey := hex.EncodeToString(util.Digest([]byte(session.ID)))
	sb, err := user.EncodeSession(session)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := cdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	sqlmock.NewRows([]string{"key", "user_id", "created_at", "blob"}).
		AddRow(sessionKey, session.UserID, session.CreatedAt, eb)

	// Queries
	sql := `DELETE FROM "sessions" WHERE "sessions"."key" = $1`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method to match queries
	err = cdb.SessionDeleteByID(session.ID)
	if err != nil {
		t.Errorf("session delete by id error: %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionDeleteByIDFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Query
	sql := `DELETE FROM "sessions" WHERE "sessions"."key" = $1`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WillReturnError(fmt.Errorf("delete sessions error"))
	mock.ExpectRollback()

	// Execute method to match queries
	err := cdb.SessionDeleteByID("random")
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionsDeleteByUserIDSuccess(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sessionKey := hex.EncodeToString(util.Digest([]byte(session.ID)))
	sb, err := user.EncodeSession(session)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := cdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	sqlmock.NewRows([]string{"key", "user_id", "created_at", "blob"}).
		AddRow(sessionKey, session.UserID, session.CreatedAt, eb)

	// Queries
	sql := `DELETE FROM "sessions" WHERE (user_id = $1)`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(session.UserID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method to match queries
	err = cdb.SessionsDeleteByUserID(session.UserID, []string{})
	if err != nil {
		t.Errorf("session delete by user id error: %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionsDeleteByUserIDFailure(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	uuid := uuid.New()

	// Queries
	sql := `DELETE FROM "sessions" WHERE (user_id = $1)`

	// Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(uuid).
		WillReturnError(fmt.Errorf("delete sessions error"))
	mock.ExpectRollback()

	// Execute method to match queries
	err := cdb.SessionsDeleteByUserID(uuid, []string{})
	if err == nil {
		t.Errorf("expecting error but got none")
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
