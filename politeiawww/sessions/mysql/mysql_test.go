// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/politeiawww/sessions"
)

// Custom go-sqlmock types for type assertion
type AnyBlob struct{}

func (a AnyBlob) Match(v driver.Value) bool {
	_, ok := v.([]byte)
	return ok
}

func setupTestDB(t *testing.T) (*mysql, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error %s while creating stub db conn", err)
	}

	m := &mysql{
		db: db,
		opts: &Opts{
			TableName: defaultTableName,
			OpTimeout: defaultOpTimeout,
		},
	}

	return m, mock, func() {
		db.Close()
	}
}

func TestSave(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	sessionID := "session-id"
	es := sessions.EncodedSession{
		Values: "dummy-session",
	}

	// Query
	sqlUpsert := fmt.Sprintf(`INSERT INTO %v 
  (id, encoded_session) VALUES (?, ?)
  ON DUPLICATE KEY UPDATE
  encoded_session = VALUES(encoded_session)`, mdb.opts.TableName)

	mock.ExpectExec(regexp.QuoteMeta(sqlUpsert)).
		WithArgs(sessionID, AnyBlob{}).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Execute method
	err := mdb.Save(sessionID, es)
	if err != nil {
		t.Errorf("Save unwanted error: %s", err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestDel(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	sessionID := "session-id"
	es := sessions.EncodedSession{
		Values: "dummy-session",
	}

	// Queries
	sqlDel := "DELETE FROM " + mdb.opts.TableName + " WHERE id = ?"
	sqlUpsert := fmt.Sprintf(`INSERT INTO %v 
  (id, encoded_session) VALUES (?, ?)
  ON DUPLICATE KEY UPDATE
  encoded_session = VALUES(encoded_session)`, mdb.opts.TableName)

	// Shouldn't error when trying to delete a session which does not
	// exist.
	mock.ExpectExec(regexp.QuoteMeta(sqlDel)).
		WithArgs(sessionID).WillReturnResult(sqlmock.NewResult(0, 0))

	// Execute Del
	err := mdb.Del(sessionID)
	if err != nil {
		t.Errorf("Del unwanted error: %s", err)
	}

	// Should result in one affected row if session exists.
	mock.ExpectExec(regexp.QuoteMeta(sqlUpsert)).
		WithArgs(sessionID, AnyBlob{}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(sqlDel)).
		WithArgs(sessionID).WillReturnResult(sqlmock.NewResult(0, 1))

	// Store session in order to test deleting a session which exists on
	// the database.
	err = mdb.Save(sessionID, es)
	if err != nil {
		t.Errorf("Save unwanted error: %s", err)
	}

	// Execute Del
	err = mdb.Del(sessionID)
	if err != nil {
		t.Errorf("Del unwanted error: %s", err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestGet(t *testing.T) {
	mdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	sessionID := "session-id"
	es := sessions.EncodedSession{
		Values: "dummy-session",
	}
	// Encode session
	esByte, err := json.Marshal(es)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Queries
	sqlSelect := "SELECT encoded_session FROM " +
		mdb.opts.TableName + " WHERE id = ?"
	sqlUpsert := fmt.Sprintf(`INSERT INTO %v
	(id, encoded_session) VALUES (?, ?)
	ON DUPLICATE KEY UPDATE
	encoded_session = VALUES(encoded_session)`, mdb.opts.TableName)

	// Should return sessions.ErrNotFound when session doesn't
	// exist on DB.
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WillReturnError(expectedError)

	// Execute Get
	esDB, err := mdb.Get(sessionID)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if esDB != nil {
		t.Errorf("not expecting a result but got one")
	}

	// Make sure we got the expected error
	if !errors.Is(err, expectedError) {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Mock session data
	rows := sqlmock.NewRows([]string{"encoded_session"}).AddRow(esByte)

	// Expect to get one row if session exists on DB
	mock.ExpectExec(regexp.QuoteMeta(sqlUpsert)).
		WithArgs(sessionID, AnyBlob{}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sessionID).
		WillReturnRows(rows)

	// Store session on DB before querying
	err = mdb.Save(sessionID, es)
	if err != nil {
		t.Errorf("Save unwanted error: %s", err)
	}

	// Execute Get
	esDB, err = mdb.Get(sessionID)
	if err != nil {
		t.Errorf("Get unwanted error: %s", err)
	}

	if esDB == nil {
		t.Errorf("expecting a result but got a nil")
	}

	// Ensure selected row equal to inserted session
	if esDB.Values != es.Values {
		t.Errorf("unexpected session value; expected: %v, got: %v", es.Values,
			esDB.Values)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
