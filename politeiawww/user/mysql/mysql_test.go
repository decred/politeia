// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/user"
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
	mysqldb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	index := newPaywallAddressIndex(t, 1)
	usr := user.User{
		Email:    "test@test.com",
		Username: "test",
	}

	// Queries
	sqlSelectIndex := `SELECT v FROM key_value WHERE k=?`
	sqlInsertUser := `INSERT INTO users ` +
		`(ID, username, uBlob, createdAt) ` +
		`VALUES ($1, $2, $3, $4)`
	sqlUpdateIndex := `UPDATE key_value SET v = $1 ` +
		`WHERE k = $2`

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
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateIndex)).
		WithArgs(sqlmock.AnyArg(), keyPaywallAddressIndex).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method
	err := mysqldb.UserNew(usr)
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
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{},
			AnyTime{}).
		WillReturnError(expectedError)
	mock.ExpectRollback()

	// Execute method
	err = mysqldb.UserNew(usr)
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
