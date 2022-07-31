// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/politeia/server/sessions"
	"github.com/pkg/errors"
)

// sessionsTable is the table for the encoded session values.
//
// The id column is 128 bytes so that it can accomidate a 64 byte base64,
// base32, or hex encoded key.
//
// The encoded_session column has a max length of 2^16 bytes, which is around
// 64KB.
//
// The created_at column contains a Unix timestamp and is used to manually
// clean up expired sessions. The gorilla/sessions Store does not do this
// automatically.
const sessionsTable = `
  id              CHAR(128) PRIMARY KEY,
  encoded_session BLOB NOT NULL,
  created_at      BIGINT NOT NULL
`

var (
	_ sessions.DB = (*mysql)(nil)
)

// mysql implements the sessions.DB interface.
type mysql struct {
	// db is the mysql DB context.
	db *sql.DB

	// sessionMaxAge is the max age of a session in seconds. This is used to
	// periodically clean up expired sessions from the database. The
	// gorilla/sessions Store implemenation does not do this automatically. It
	// must be done manually in the database layer.
	sessionMaxAge int64

	// opts contains the session database options.
	opts *Opts
}

// Opts contains configurable options for the sessions database. These are
// not required. Sane defaults are used when the options are not provided.
type Opts struct {
	// TableName is the table name for the sessions table.
	TableName string

	// OpTimeout is the timeout for a single database operation.
	OpTimeout time.Duration
}

const (
	// defaultTableName is the default table name for the sessions table.
	defaultTableName = "sessions"

	// defaultOpTimeout is the default timeout for a single database operation.
	defaultOpTimeout = 1 * time.Minute
)

// New returns a new mysql context that implements the sessions DB interface.
// The opts param can be used to override the default mysql context settings.
//
// The sessionMaxAge is the max age in seconds of a session. This function
// cleans up any expired sessions from the database as part of the
// initialization. A sessionMaxAge of <=0 will cause the sessions database
// to be dropped and recreated.
func New(db *sql.DB, sessionMaxAge int64, opts *Opts) (*mysql, error) {
	// Setup the database options
	if opts == nil {
		opts = &Opts{}
	}
	if opts.TableName == "" {
		opts.TableName = defaultTableName
	}
	if opts.OpTimeout == 0 {
		opts.OpTimeout = defaultOpTimeout
	}

	// Setup the mysql context
	m := mysql{
		db:            db,
		sessionMaxAge: sessionMaxAge,
		opts:          opts,
	}

	// Perform database setup
	if sessionMaxAge <= 0 {
		err := m.dropTable()
		if err != nil {
			return nil, err
		}
	}
	err := m.createTable()
	if err != nil {
		return nil, err
	}
	err = m.cleanup()
	if err != nil {
		return nil, err
	}

	return &m, nil
}

// Save saves a session to the database.
//
// Save satisfies the sessions.DB interface.
func (m *mysql) Save(sessionID string, s sessions.EncodedSession) error {
	log.Tracef("Save %v", sessionID)

	es, err := json.Marshal(s)
	if err != nil {
		return err
	}

	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := `INSERT INTO %v
    (id, encoded_session, created_at) VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE
    encoded_session = VALUES(encoded_session)`

	q = fmt.Sprintf(q, m.opts.TableName)
	_, err = m.db.ExecContext(ctx, q, sessionID, es, time.Now().Unix())
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Del deletes a session from the database. An error is not returned if the
// session does not exist.
//
// Del satisfies the sessions.DB interface.
func (m *mysql) Del(sessionID string) error {
	log.Tracef("Del %v", sessionID)

	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := fmt.Sprintf("DELETE FROM %v WHERE id = ?", m.opts.TableName)
	_, err := m.db.ExecContext(ctx, q, sessionID)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Get gets a session from the database. An ErrNotFound error is returned if
// a session is not found for the session ID.
//
// Get statisfies the sessions.DB interface.
func (m *mysql) Get(sessionID string) (*sessions.EncodedSession, error) {
	log.Tracef("Get %v", sessionID)

	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := fmt.Sprintf("SELECT encoded_session FROM %v WHERE id = ?",
		m.opts.TableName)

	var encodedBlob []byte
	err := m.db.QueryRowContext(ctx, q, sessionID).Scan(&encodedBlob)
	switch {
	case err == sql.ErrNoRows:
		return nil, sessions.ErrNotFound
	case err != nil:
		return nil, errors.WithStack(err)
	}

	var es sessions.EncodedSession
	err = json.Unmarshal(encodedBlob, &es)
	if err != nil {
		return nil, err
	}

	return &es, nil
}

// createTable creates the sessions table.
func (m *mysql) createTable() error {
	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (%v)",
		m.opts.TableName, sessionsTable)
	_, err := m.db.ExecContext(ctx, q)
	if err != nil {
		return errors.WithStack(err)
	}

	log.Debugf("Created %v database table", m.opts.TableName)

	return nil
}

// dropTable drops the sessions table.
func (m *mysql) dropTable() error {
	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := fmt.Sprintf("DROP TABLE IF EXISTS %v", m.opts.TableName)
	_, err := m.db.ExecContext(ctx, q)
	if err != nil {
		return errors.WithStack(err)
	}

	log.Debugf("Dropped %v database table", m.opts.TableName)

	return nil
}

// cleanup performs database cleanup by deleting all sessions that have
// expired.
func (m *mysql) cleanup() error {
	ctx, cancel := m.ctxForOp()
	defer cancel()

	q := "DELETE FROM %v WHERE created_at + ? <= ?"
	q = fmt.Sprintf(q, m.opts.TableName)
	r, err := m.db.ExecContext(ctx, q, m.sessionMaxAge, time.Now().Unix())
	if err != nil {
		return errors.WithStack(err)
	}
	rowsAffected, err := r.RowsAffected()
	if err != nil {
		return err
	}

	log.Debugf("Deleted %v expired sessions from the database", rowsAffected)

	return nil
}

// ctxForOp returns a context and cancel function for a single database
// operation.
func (m *mysql) ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), m.opts.OpTimeout)
}
