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

	"github.com/decred/politeia/politeiawww/sessions"
)

const (
	// defaultTableName is the default table name for the sessions table.
	defaultTableName = "sessions"

	// defaultOpTimeout is the default timeout for a single database operation.
	defaultOpTimeout = 1 * time.Minute
)

// tableSessions defines the sessions table.
//
// id column is 128 bytes so that it can accomidate a 64 byte base64, base32,
// or hex encoded key.
//
// encoded_session column max length is up to 2^16 bytes which is around 64KB.
const tableSessions = `
  id              CHAR(128) NOT NULL PRIMARY KEY,
  encoded_session BLOB NOT NULL
`

// Opts includes configurable options for the sessions database.
type Opts struct {
	// TableName is the table name for the sessions table. Defaults to
	// "sessions".
	TableName string

	// OpTimeout is the timeout for a single database operation. Defaults to
	// 1 minute.
	OpTimeout time.Duration
}

var (
	_ sessions.DB = (*mysql)(nil)
)

// mysql implements the sessions.DB interface.
type mysql struct {
	// db is the mysql DB context.
	db *sql.DB

	// opts includes the sessions database options.
	opts *Opts
}

// ctxForOp returns a context and cancel function for a single database
// operation. It uses the database operation timeout set on the mysql
// context.
func (m *mysql) ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), m.opts.OpTimeout)
}

// Save saves a session to the database.
//
// Save satisfies the sessions.DB interface.
func (m *mysql) Save(sessionID string, s sessions.EncodedSession) error {
	log.Tracef("Save: %v", sessionID)

	// Marshal encoded session
	es, err := json.Marshal(s)
	if err != nil {
		return err
	}

	ctx, cancel := m.ctxForOp()
	defer cancel()

	// Save session to database
	q := fmt.Sprintf(`INSERT INTO %v 
  (id, encoded_session) VALUES (?, ?)
  ON DUPLICATE KEY UPDATE
  encoded_session = VALUES(encoded_session)`, m.opts.TableName)
	_, err = m.db.ExecContext(ctx, q, sessionID, es)
	if err != nil {
		return err
	}

	return nil
}

// Del deletes a session from the database. An error is not returned if the
// session does not exist.
//
// Del satisfies the sessions.DB interface.
func (m *mysql) Del(sessionID string) error {
	log.Tracef("Del: %v", sessionID)

	ctx, cancel := m.ctxForOp()
	defer cancel()

	// Delete session
	_, err := m.db.ExecContext(ctx,
		"DELETE FROM "+m.opts.TableName+" WHERE id = ?", sessionID)
	if err != nil {
		return err
	}

	return nil
}

// Get gets a session from the database. An ErrNotFound error is returned if
// a session is not found for the session ID.
//
// Get statisfies the sessions.DB interface.
func (m *mysql) Get(sessionID string) (*sessions.EncodedSession, error) {
	log.Tracef("Get: %v", sessionID)

	ctx, cancel := m.ctxForOp()
	defer cancel()

	// Get session
	var encodedBlob []byte
	err := m.db.QueryRowContext(ctx,
		"SELECT encoded_session FROM "+m.opts.TableName+" WHERE id = ?",
		sessionID).Scan(&encodedBlob)
	switch {
	case err == sql.ErrNoRows:
		return nil, sessions.ErrNotFound
	case err != nil:
		return nil, err
	}

	// Decode blob
	var es sessions.EncodedSession
	err = json.Unmarshal(encodedBlob, &es)
	if err != nil {
		return nil, err
	}

	return &es, nil
}

// New returns a new mysql context that implements the sessions DB interface.
// The opts param can be used to override the default mysql context settings.
func New(db *sql.DB, opts *Opts) (*mysql, error) {
	// Setup database options.
	tableName := defaultTableName
	opTimeout := defaultOpTimeout
	// Override defaults if options are provided
	if opts != nil {
		if opts.TableName != "" {
			tableName = opts.TableName
		}
		if opts.OpTimeout != 0 {
			opTimeout = opts.OpTimeout
		}
	}

	// Create mysql context
	m := mysql{
		db: db,
		opts: &Opts{
			TableName: tableName,
			OpTimeout: opTimeout,
		},
	}

	ctx, cancel := m.ctxForOp()
	defer cancel()

	// Create sessions table
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		m.opts.TableName, tableSessions)
	_, err := db.ExecContext(ctx, q)
	if err != nil {
		return nil, err
	}

	return &m, nil
}
