// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/sessions"
)

// newTestMySQL returns a mysql context that has been setup for testing along
// with the sql mocking context and a cleanup function. Invocation of the
// cleanup function should be deferred by the caller.
func newTestMySQL(t *testing.T) (*mysql, sqlmock.Sqlmock, func()) {
	t.Helper()

	// sqlmock defaults to using the expected SQL string as a regular
	// expression to match incoming query strings. The QueryMatcherEqual
	// overrides this default behavior and does a full case sensitive
	// match.
	opts := sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual)
	db, mock, err := sqlmock.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		defer db.Close()
	}
	m := &mysql{
		db:            db,
		sessionMaxAge: 1,
		opts: &Opts{
			TableName: defaultTableName,
			OpTimeout: defaultOpTimeout,
		},
	}

	return m, mock, cleanup
}

func TestSave(t *testing.T) {
	m, mock, cleanup := newTestMySQL(t)
	defer cleanup()

	// Setup the test data
	var (
		sessionID = "test-session-id"
		es        = sessions.EncodedSession{
			Values: "test-values",
		}
	)
	esB, err := json.Marshal(es)
	if err != nil {
		t.Fatal(err)
	}

	q := `INSERT INTO %v
    (id, encoded_session, created_at) VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE
    encoded_session = VALUES(encoded_session)`

	q = fmt.Sprintf(q, m.opts.TableName)

	// Test the unexpected error path
	unexpectedErr := errors.New("unexpected error")
	mock.ExpectExec(q).
		WithArgs(sessionID, esB, AnyInt64{}).
		WillReturnError(unexpectedErr)

	err = m.Save(sessionID, es)
	if !errors.Is(err, unexpectedErr) {
		t.Errorf("got err '%v', want '%v'", err, unexpectedErr)
	}

	// Test the success path
	mock.ExpectExec(q).
		WithArgs(sessionID, esB, AnyInt64{}).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = m.Save(sessionID, es)
	if err != nil {
		t.Error(err)
	}
}

func TestDel(t *testing.T) {
	m, mock, cleanup := newTestMySQL(t)
	defer cleanup()

	// Setup the test data
	var (
		q = fmt.Sprintf("DELETE FROM %v WHERE id = ?", m.opts.TableName)

		sessionID = "test-session-id"
	)

	// Test the unexpected error path
	unexpectedErr := errors.New("unexpected error")
	mock.ExpectExec(q).
		WithArgs(sessionID).
		WillReturnError(unexpectedErr)

	err := m.Del(sessionID)
	if !errors.Is(err, unexpectedErr) {
		t.Errorf("got err '%v', want '%v'", err, unexpectedErr)
	}

	// Test the success path
	mock.ExpectExec(q).
		WithArgs(sessionID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = m.Del(sessionID)
	if err != nil {
		t.Error(err)
	}
}

func TestGet(t *testing.T) {
	m, mock, cleanup := newTestMySQL(t)
	defer cleanup()

	// Setup the test data
	var (
		q = fmt.Sprintf("SELECT encoded_session FROM %v WHERE id = ?",
			m.opts.TableName)

		sessionID = "test-session-id"
		es        = sessions.EncodedSession{
			Values: "test-values",
		}
	)
	esB, err := json.Marshal(es)
	if err != nil {
		t.Fatal(err)
	}

	// Test the not found error path
	mock.ExpectQuery(q).
		WithArgs(sessionID).
		WillReturnError(sql.ErrNoRows)

	_, err = m.Get(sessionID)
	if !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("got err '%v', want '%v'", err, sessions.ErrNotFound)
	}

	// Test the unexpected error path
	unexpectedErr := errors.New("unexpected error")
	mock.ExpectQuery(q).
		WithArgs(sessionID).
		WillReturnError(unexpectedErr)

	_, err = m.Get(sessionID)
	if !errors.Is(err, unexpectedErr) {
		t.Errorf("got err '%v', want '%v'", err, unexpectedErr)
	}

	// Test the success path
	rows := sqlmock.NewRows([]string{"encoded_session"}).AddRow(esB)
	mock.ExpectQuery(q).
		WithArgs(sessionID).
		WillReturnRows(rows)

	r, err := m.Get(sessionID)
	switch {
	case err != nil:
		t.Error(err)
	case r == nil:
		t.Errorf("got nil session, want %+v", es)
	case r.Values != es.Values:
		t.Errorf("got sesions values '%v', want '%v'", r.Values, es.Values)
	}
}

// AnyInt64 can be passed in as a sqlmock prepared statement argument when the
// caller knows that the argument will be an int64, but does not know what the
// exact value of the int64 will be.
type AnyInt64 struct{}

// Match satisfies sqlmock Argument interface.
func (a AnyInt64) Match(v driver.Value) bool {
	_, ok := v.(int64)
	return ok
}
