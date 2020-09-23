// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
var (
	errSelect = fmt.Errorf("select user error")
	errDelete = fmt.Errorf("delete user error")
)

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

	// Execute method
	err := cdb.SetPaywallAddressIndex(i)
	if err != nil {
		t.Errorf("SetPaywallAddressIndex unwanted err %s", err)
	}

	// Make sure query expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserNew(t *testing.T) {
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
	sqlInsertUser := `INSERT INTO "users" ` +
		`("id","username","blob","created_at","updated_at") ` +
		`VALUES ($1,$2,$3,$4,$5) ` +
		`RETURNING "users"."id"`
	sqlUpdateIndex := `UPDATE "key_value" SET "value" = $1 ` +
		`WHERE "key_value"."key" = $2`

	// Success Expectations
	mock.ExpectBegin()
	// Select paywall address index
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value"}).
			AddRow(keyPaywallAddressIndex, index))
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{},
			AnyTime{}, AnyTime{}).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(usr.ID))
	// Update paywall address index
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateIndex)).
		WithArgs(sqlmock.AnyArg(), keyPaywallAddressIndex).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UserNew(usr)
	if err != nil {
		t.Errorf("UserNew unwanted error: %s", err)
	}

	// Negative Expectations
	expectedError := user.ErrUserExists
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value"}).
			AddRow(keyPaywallAddressIndex, index))
	// User already exists error
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{},
			AnyTime{}, AnyTime{}).
		WillReturnError(expectedError)
	mock.ExpectRollback()

	// Execute method
	err = cdb.UserNew(usr)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure we got the expected error
	if err.Error() != fmt.Errorf("create user: %v", expectedError).Error() {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserUpdate(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	id := uuid.New()
	usr := user.User{
		ID:         id,
		Identities: []user.Identity{},
		Email:      "test@test.com",
		Username:   "test",
	}

	// Query
	sql := `UPDATE "users" ` +
		`SET "username" = $1, "blob" = $2, "updated_at" = $3 ` +
		`WHERE "users"."id" = $4`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username, AnyBlob{}, AnyTime{}, usr.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UserUpdate(usr)
	if err != nil {
		t.Errorf("UserUpdate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByUsername(t *testing.T) {
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

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username).
		WillReturnRows(rows)

	// Execute method
	u, err := cdb.UserGetByUsername(usr.Username)
	if err != nil {
		t.Errorf("UserGetByUsername unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	if u.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, u.ID)
	}

	// Negative Expectations
	randomUsername := "random"
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomUsername).
		WillReturnError(expectedError)

	// Execute method
	u, err = cdb.UserGetByUsername(randomUsername)
	if err == nil {
		t.Errorf("expecting error %s, but there was none", expectedError)
	}

	// Make sure no user was fetched
	if u != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", u.ID)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetById(t *testing.T) {
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

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.ID).
		WillReturnRows(rows)

	// Execute method
	u, err := cdb.UserGetById(usr.ID)
	if err != nil {
		t.Errorf("UserGetById unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	if u.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, u.ID)
	}

	// Negative Expectations
	expectedError := user.ErrUserNotFound
	randomID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomID).
		WillReturnError(expectedError)

	// Execute method
	u, err = cdb.UserGetById(randomID)
	if err == nil {
		t.Errorf("expecting error %s, but there was none", expectedError)
	}

	// Make sure no user was fetched
	if u != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", u.ID)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUserGetByPubKey(t *testing.T) {
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
	sql := `SELECT * FROM users ` +
		`INNER JOIN identities ON users.id = identities.user_id ` +
		`WHERE identities.public_key = $1`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method
	ur, err := cdb.UserGetByPubKey(pubkey)
	if err != nil {
		t.Errorf("UserGetByPubKey unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	if ur.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, ur.ID)
	}

	// Negative Expectations
	randomUsr, _ := newCdbUser(t, cdb)
	randomPubkey := randomUsr.Identities[0].PublicKey
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomPubkey).
		WillReturnError(expectedError)

	// Execute method
	ur, err = cdb.UserGetByPubKey(randomPubkey)
	if err == nil {
		t.Errorf("expecting error user not found, but there was none")
	}

	// Make sure no user was fetched
	if ur != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", ur.ID)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUsersGetByPubKey(t *testing.T) {
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
	sql := `SELECT * FROM users ` +
		`INNER JOIN identities ON users.id = identities.user_id ` +
		`WHERE identities.public_key IN ($1)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method
	ur, err := cdb.UsersGetByPubKey([]string{pubkey})
	if err != nil {
		t.Errorf("UsersGetByPubKey unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	fetchedUser := ur[pubkey]
	if fetchedUser.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s",
			usr.ID, fetchedUser.ID)
	}

	// Negative Expectations
	randomUsr, _ := newCdbUser(t, cdb)
	randomPubkey := randomUsr.Identities[0].PublicKey
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomPubkey).
		WillReturnError(expectedError)

	// Execute method
	ur, err = cdb.UsersGetByPubKey([]string{randomPubkey})
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure no user was fetched
	if len(ur) != 0 {
		t.Errorf("expecting nil user to be returned, but got user %s",
			ur[randomPubkey].ID)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestAllUsers(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)
	usr2, blob2 := newCdbUser(t, cdb)

	// Query
	sql := `SELECT * FROM "users"`

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

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnRows(rows)

	// Execute method
	var users []user.User
	err := cdb.AllUsers(func(u *user.User) {
		users = append(users, *u)
	})
	if err != nil {
		t.Errorf("AllUsers unwanted error: %s", err)
	}

	// Check if both mocked users were returned
	if len(users) != 2 {
		t.Errorf("did not return all users")
	}

	// Negative Expectations
	expectedError := gorm.ErrRecordNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnError(expectedError)

	// Execute method
	var us []user.User
	err = cdb.AllUsers(func(u *user.User) {
		us = append(us, *u)
	})
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure no users were returned
	if len(us) != 0 {
		t.Errorf("expected no users but returned %v users", len(us))
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionSave(t *testing.T) {
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

	sqlInsert := `INSERT INTO "sessions" ` +
		`("key","user_id","created_at","blob") ` +
		`VALUES ($1,$2,$3,$4) RETURNING "sessions"."key"`

	// Success Create Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnRows(sqlmock.NewRows([]string{}))
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsert)).
		WithArgs(sessionKey, session.UserID, session.CreatedAt, AnyBlob{}).
		WillReturnRows(sqlmock.NewRows([]string{"key"}).AddRow(sessionKey))
	mock.ExpectCommit()

	// Execute method
	err := cdb.SessionSave(session)
	if err != nil {
		t.Errorf("SessionSave unwanted error: %s", err)
	}

	// Mock data for updating a user session
	rows := sqlmock.NewRows([]string{"key", "user_id", "created_at", "blob"}).
		AddRow(sessionKey, session.UserID, session.CreatedAt, []byte{})

	// Queries
	sqlUpdate := `UPDATE "sessions" ` +
		`SET "user_id" = $1, "created_at" = $2, "blob" = $3 ` +
		`WHERE "sessions"."key" = $4`

	// Success Update Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnRows(rows)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(session.UserID, session.CreatedAt, AnyBlob{}, sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err = cdb.SessionSave(session)
	if err != nil {
		t.Errorf("SessionSave unwanted error: %s", err)
	}

	// Negative Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WillReturnError(errSelect)

	// Execute method
	err = cdb.SessionSave(user.Session{})
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionGetByID(t *testing.T) {
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

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnRows(rows)

	// Execute method
	s, err := cdb.SessionGetByID(session.ID)
	if err != nil {
		t.Errorf("SessionGetByID unwanted error: %s", err)
	}

	// Make sure correct session was returned
	if session.ID != s.ID {
		t.Errorf("expecting session %s but got %s", session.ID, s.ID)
	}

	// Negative Expectations
	randomID := "2"
	randomKey := hex.EncodeToString(util.Digest([]byte(randomID)))
	expectedError := user.ErrSessionNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomKey).
		WillReturnError(expectedError)

	// Execute method
	s, err = cdb.SessionGetByID(randomID)
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure no sessions were returned
	if s != nil {
		t.Errorf("expected no session but got %v", s)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionDeleteByID(t *testing.T) {
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

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err = cdb.SessionDeleteByID(session.ID)
	if err != nil {
		t.Errorf("SessionDeleteByID unwanted error: %s", err)
	}

	// Negative Expectations
	randomID := "random"
	randomKey := hex.EncodeToString(util.Digest([]byte(randomID)))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(randomKey).
		WillReturnError(errDelete)
	mock.ExpectRollback()

	// Execute method
	err = cdb.SessionDeleteByID(randomID)
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure we got the expected error
	if err != errDelete {
		t.Errorf("expecting error %s but got %s", errDelete, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSessionsDeleteByUserID(t *testing.T) {
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

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(session.UserID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err = cdb.SessionsDeleteByUserID(session.UserID, []string{})
	if err != nil {
		t.Errorf("SessionsDeleteByUserID unwanted error: %s", err)
	}

	// Negative Expectations
	randomID := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(randomID).
		WillReturnError(errDelete)
	mock.ExpectRollback()

	// Execute method
	err = cdb.SessionsDeleteByUserID(randomID, []string{})
	if err == nil {
		t.Errorf("expecting error but got none")
	}

	// Make sure we got the expected error
	if err != errDelete {
		t.Errorf("expecting error %s but got %s", errDelete, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
