// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// Custom go-sqlmock types for type assertion
type AnyBlob struct{}
type AnyTime struct{}

func (a AnyBlob) Match(v driver.Value) bool {
	_, ok := v.([]byte)
	return ok
}

func (a AnyTime) Match(v driver.Value) bool {
	_, ok := v.(int64)
	return ok
}

// Helpers
var (
	errSelect = fmt.Errorf("select user error")
	errDelete = fmt.Errorf("delete user error")
)

func newUser(t *testing.T, mdb *mysql) (user.User, []byte) {
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
	eb, err := mdb.encrypt(user.VersionUser, eu)
	if err != nil {
		t.Fatalf("%s", err)
	}

	return u, eb
}

func setupTestDB(t *testing.T) (*mysql, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error %s while creating stub db conn", err)
	}

	b := []byte("random")
	var key [32]byte
	copy(key[:], b)

	c := &mysql{
		userDB:        db,
		encryptionKey: &key,
	}

	return c, mock, func() {
		db.Close()
	}
}

func newPaywallAddressIndex(t *testing.T, i uint64) *[]byte {
	t.Helper()

	index := make([]byte, 8)
	binary.LittleEndian.PutUint64(index, i)
	return &index
}

// Tests
func TestUserNew(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	index := newPaywallAddressIndex(t, 1)
	usr := user.User{
		Email:    "test@test.com",
		Username: "test",
	}

	// Queries
	sqlSelectIndex := `SELECT v FROM key_value WHERE k = ?`
	sqlInsertUser := `INSERT INTO users ` +
		`(id, username, u_blob, created_at) ` +
		`VALUES (?, ?, ?, ?)`
	sqlUpsertIndex := `INSERT INTO key_value (k,v)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE
    v = ?`

	// Success Expectations
	mock.ExpectBegin()
	// Select paywall address index
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"v"}).
			AddRow(index))
	// Insert user to db
	mock.ExpectExec(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{}, AnyTime{}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Update paywall address index
	mock.ExpectExec(regexp.QuoteMeta(sqlUpsertIndex)).
		WithArgs(keyPaywallAddressIndex, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method
	err := mdb.UserNew(usr)
	if err != nil {
		t.Errorf("UserNew unwanted error: %s", err)
	}

	// Negative Expectations
	expectedError := user.ErrUserExists
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"v"}).
			AddRow(index))
	// User already exists error
	mock.ExpectExec(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{}, AnyTime{}).
		WillReturnError(expectedError)
	mock.ExpectRollback()

	// Execute method
	err = mdb.UserNew(usr)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure we got the expected error
	wantErr := fmt.Errorf("create user: %v", expectedError)
	if err.Error() != wantErr.Error() {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	id := uuid.New()
	usr := user.User{
		ID:         id,
		Identities: []user.Identity{},
		Email:      "test@test.com",
		Username:   "test",
	}

	// Update user query
	uq := `UPDATE users ` +
		`SET username = ?, u_blob = ?, updated_at = ? ` +
		`WHERE id = ?`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(uq)).
		WithArgs(usr.Username, AnyBlob{}, AnyTime{}, usr.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Upsert user identities query
	iq := "INSERT INTO identities (public_key, user_id, activated, deactivated) " +
		"VALUES ON DUPLICATE KEY UPDATE " +
		"activated=VALUES(activated), deactivated=VALUES(deactivated)"

	mock.ExpectExec(regexp.QuoteMeta(iq)).
		WithArgs().
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := mdb.UserUpdate(usr)
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	usr, blob := newUser(t, mdb)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"u_blob",
	}).AddRow(blob)

	// Query
	sql := `SELECT u_blob FROM users WHERE username = ?`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username).
		WillReturnRows(rows)

	// Execute method
	u, err := mdb.UserGetByUsername(usr.Username)
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
	u, err = mdb.UserGetByUsername(randomUsername)
	if err == nil {
		t.Errorf("expecting error %s, but there was none", expectedError)
	}

	// Make sure no user was fetched
	if u != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", u.ID)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	usr, blob := newUser(t, mdb)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"u_blob",
	}).AddRow(blob)

	// Query
	sql := `SELECT u_blob FROM users WHERE id = ?`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.ID).
		WillReturnRows(rows)

	// Execute method
	u, err := mdb.UserGetById(usr.ID)
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
	u, err = mdb.UserGetById(randomID)
	if err == nil {
		t.Errorf("expecting error %s, but there was none", expectedError)
	}

	// Make sure no user was fetched
	if u != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", u.ID)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	usr, blob := newUser(t, mdb)
	pubkey := usr.Identities[0].String()

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"u_blob",
	}).AddRow(blob)

	// Query
	sql := `SELECT u_blob FROM users ` +
		`INNER JOIN identities ON users.id = identities.user_id ` +
		`WHERE identities.public_key = ?`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method
	ur, err := mdb.UserGetByPubKey(pubkey)
	if err != nil {
		t.Errorf("UserGetByPubKey unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	if ur.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, ur.ID)
	}

	// Negative Expectations
	randomUsr, _ := newUser(t, mdb)
	randomPubkey := randomUsr.Identities[0].String()
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomPubkey).
		WillReturnError(expectedError)

	// Execute method
	ur, err = mdb.UserGetByPubKey(randomPubkey)
	if err == nil {
		t.Errorf("expecting error user not found, but there was none")
	}

	// Make sure no user was fetched
	if ur != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", ur.ID)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	usr, blob := newUser(t, mdb)
	pubkey := usr.Identities[0].String()

	// Mock data
	rows := sqlmock.NewRows([]string{
		"u_blob",
	}).AddRow(blob)

	// Query
	sql := `SELECT u_blob FROM users ` +
		`INNER JOIN identities ON users.id = identities.user_id ` +
		`WHERE identities.public_key IN (?)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(pubkey).
		WillReturnRows(rows)

	// Execute method
	ur, err := mdb.UsersGetByPubKey([]string{pubkey})
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
	randomUsr, _ := newUser(t, mdb)
	randomPubkey := randomUsr.Identities[0].String()
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomPubkey).
		WillReturnError(expectedError)

	// Execute method
	ur, err = mdb.UsersGetByPubKey([]string{randomPubkey})
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure no user was fetched
	if len(ur) != 0 {
		t.Errorf("expecting nil user to be returned, but got user %s",
			ur[randomPubkey].ID)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	_, blob := newUser(t, mdb)
	_, blob2 := newUser(t, mdb)

	// Query
	sql := `SELECT u_blob FROM users`

	// Mock data
	rows := sqlmock.NewRows([]string{
		"u_blob",
	}).
		AddRow(blob).
		AddRow(blob2)

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnRows(rows)

	// Execute method
	var users []user.User
	err := mdb.AllUsers(func(u *user.User) {
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
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WillReturnError(expectedError)

	// Execute method
	var us []user.User
	err = mdb.AllUsers(func(u *user.User) {
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
	if !errors.Is(err, expectedError) {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEmailHistoriesSave(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	userID := uuid.New()
	histories := make(map[uuid.UUID]user.EmailHistory, 1)
	histories[userID] = user.EmailHistory{
		Timestamps:       []int64{time.Now().Unix()},
		LimitWarningSent: false,
	}

	// Queries
	sqlSelect := `SELECT user_id FROM email_histories WHERE user_id = ?`

	sqlInsert := `INSERT INTO email_histories (user_id, h_blob) VALUES (?, ?)`

	// Success create expectations
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(userID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(sqlInsert)).
		WithArgs(userID, AnyBlob{}).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := mdb.EmailHistoriesSave(histories)
	if err != nil {
		t.Errorf("EmailHistoriesSave unwanted error: %s", err)
	}

	// Mock data for updating an email history
	rows := sqlmock.NewRows([]string{"h_blob"}).AddRow([]byte{})

	// Query
	sqlUpdate := `UPDATE email_histories SET h_blob = ? WHERE user_id = ?`

	// Success update expectations
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(userID).
		WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(AnyBlob{}, userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err = mdb.EmailHistoriesSave(histories)
	if err != nil {
		t.Errorf("EmailHistoriesSave unwanted error: %s", err)
	}

	// Negative expectations
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WillReturnError(errSelect)
	mock.ExpectRollback()

	// Execute method
	badHistories := make(map[uuid.UUID]user.EmailHistory, 1)
	badHistories[uuid.New()] = user.EmailHistory{}
	err = mdb.EmailHistoriesSave(badHistories)
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

func TestEmailHistoriesGet(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	userID := uuid.New()
	ts := time.Now().Unix()
	history := user.EmailHistory{
		Timestamps:       []int64{ts},
		LimitWarningSent: false,
	}
	hb, err := json.Marshal(history)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := mdb.encrypt(user.VersionEmailHistory, hb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	rows := sqlmock.NewRows([]string{"user_id", "h_blob"}).
		AddRow(userID, eb)

	// Query
	sql := `SELECT user_id, h_blob FROM email_histories WHERE user_id IN (?)`

	// Success expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(userID).
		WillReturnRows(rows)

	// Execute method
	eh, err := mdb.EmailHistoriesGet([]uuid.UUID{userID})
	if err != nil {
		t.Errorf("EmailHistoriesGet unwanted error: %s", err)
	}

	// Make sure correct history was returned
	if ts != eh[userID].Timestamps[0] {
		t.Errorf("expecting timestamp %d but got %d",
			ts, eh[userID].Timestamps[0])
	}

	// Negative expectations
	randomUserID := uuid.New()
	expectedError := errors.New("email history not found")
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomUserID).
		WillReturnError(expectedError)

	// Execute method
	h, err := mdb.EmailHistoriesGet([]uuid.UUID{randomUserID})
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure no sessions were returned
	if h != nil {
		t.Errorf("expected no email history but got %v", h)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
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
	sqlSelect := `SELECT k FROM sessions WHERE k = ?`

	sqlInsert := `INSERT INTO sessions ` +
		`(k, user_id, created_at, s_blob) ` +
		`VALUES (?, ?, ?, ?)`

	// Success Create Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(sqlInsert)).
		WithArgs(sessionKey, session.UserID, session.CreatedAt, AnyBlob{}).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute method
	err := mdb.SessionSave(session)
	if err != nil {
		t.Errorf("SessionSave unwanted error: %s", err)
	}

	// Mock data for updating a user session
	rows := sqlmock.NewRows([]string{"s_blob"}).
		AddRow([]byte{})

	// Queries
	sqlUpdate := `UPDATE sessions ` +
		`SET user_id = ?, created_at = ?, s_blob = ? ` +
		`WHERE k = ?`

	// Success Update Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionKey).
		WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(session.UserID, session.CreatedAt, AnyBlob{}, sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute method
	err = mdb.SessionSave(session)
	if err != nil {
		t.Errorf("SessionSave unwanted error: %s", err)
	}

	// Negative Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WillReturnError(errSelect)

	// Execute method
	err = mdb.SessionSave(user.Session{})
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
	mdb, mock, close := setupTestDB(t)
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
	eb, err := mdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	rows := sqlmock.NewRows([]string{"s_blob"}).
		AddRow(eb)

	// Queries
	sql := `SELECT s_blob FROM sessions WHERE k = ?`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnRows(rows)

	// Execute method
	s, err := mdb.SessionGetByID(session.ID)
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
	s, err = mdb.SessionGetByID(randomID)
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure no sessions were returned
	if s != nil {
		t.Errorf("expected no session but got %v", s)
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
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
	mdb, mock, close := setupTestDB(t)
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
	eb, err := mdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	sqlmock.NewRows([]string{"s_blob"}).
		AddRow(eb)

	// Queries
	sql := `DELETE FROM sessions WHERE k = ?`

	// Success Expectations
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(sessionKey).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute method
	err = mdb.SessionDeleteByID(session.ID)
	if err != nil {
		t.Errorf("SessionDeleteByID unwanted error: %s", err)
	}

	// Negative Expectations
	randomID := "random"
	randomKey := hex.EncodeToString(util.Digest([]byte(randomID)))
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(randomKey).
		WillReturnError(errDelete)

	// Execute method
	err = mdb.SessionDeleteByID(randomID)
	if err == nil {
		t.Errorf("expected error but there was none")
	}

	// Make sure we got the expected error
	if !errors.Is(err, errDelete) {
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
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	session := user.Session{
		ID:        "1",
		UserID:    uuid.New(),
		CreatedAt: time.Now().Unix(),
		Values:    "",
	}
	sb, err := user.EncodeSession(session)
	if err != nil {
		t.Fatalf("%s", err)
	}
	eb, err := mdb.encrypt(user.VersionSession, sb)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Mock data
	sqlmock.NewRows([]string{"s_blob"}).
		AddRow(eb)

	// Queries
	sql := `DELETE FROM sessions WHERE user_id = ?`

	// Success Expectations
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(session.UserID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute method
	err = mdb.SessionsDeleteByUserID(session.UserID, []string{})
	if err != nil {
		t.Errorf("SessionsDeleteByUserID unwanted error: %s", err)
	}

	// Negative Expectations
	randomID := uuid.New()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(randomID).
		WillReturnError(errDelete)

	// Execute method
	err = mdb.SessionsDeleteByUserID(randomID, []string{})
	if err == nil {
		t.Errorf("expecting error but got none")
	}

	// Make sure we got the expected error
	if !errors.Is(err, errDelete) {
		t.Errorf("expecting error %s but got %s", errDelete, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSetPaywallAddressIndex(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Query
	sqlUpsertIndex := `INSERT INTO key_value (k,v)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE
    v = ?`

	// Success Expectations
	mock.ExpectBegin()
	// Upsert paywall address index
	mock.ExpectExec(regexp.QuoteMeta(sqlUpsertIndex)).
		WithArgs(keyPaywallAddressIndex, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method
	err := mdb.SetPaywallAddressIndex(7)
	if err != nil {
		t.Errorf("SetPaywallAddressIndex unwanted error: %s", err)
	}

	// Negative Expectations
	expectedError := fmt.Errorf("some error")
	mock.ExpectBegin()
	// User already exists error
	mock.ExpectExec(regexp.QuoteMeta(sqlUpsertIndex)).
		WithArgs(keyPaywallAddressIndex, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(expectedError)
	mock.ExpectRollback()

	// Execute method
	err = mdb.SetPaywallAddressIndex(7)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
