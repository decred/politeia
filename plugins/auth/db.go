// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

var (
	// errNotFound is returned when a record is not found in the database.
	errNotFound = errors.New("not found")
)

// querier contains the sql query methods.
//
// The querier interface is used so that query code does not need to be
// duplicated for atomic and non-atomic queries. The caller can use either
// a sql.Tx or the sql.DB as the querier depending on whether they need the
// query to be atomic.
type querier interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// usersTable is the database table for user data.
//
// encrypted contains the full user object as a JSON encoded, encrypted blob.
// Some public fields are duplicated in clear text so that they can be queried
// using SQL.
const usersTable = `
  uuid       CHAR(36) PRIMARY KEY,
  username   VARCHAR(64) NOT NULL UNIQUE,
  created_at BIGINT NOT NULL,
  encrypted  LONGBLOB
`

// groupsTable is the database table for user groups. A user can be a part
// of many groups.
const groupsTable = `
  id          INT PRIMARY KEY AUTO_INCREMENT,
  uuid        CHAR(36),
  user_group  VARCHAR(64) NOT NULL,
  created_at  BIGINT NOT NULL,
  FOREIGN KEY (uuid) REFERENCES auth_users(uuid)
`

// contactsTable is a database table that is used to lookup a user ID based
// on their contact information.
//
// For example, a user that wishes to reset their password can do so by
// providing the email address for the account. This table allows us to lookup
// the user ID using the email address.
//
// contact_hash is a base64 encoded bcyrpt hash of the contact information.
// It's hashed using bcrypt to add a layer of protection in the event that the
// database is compromised.
//
// Contact information is not required to be unique, so it's possible that a
// contact hash corresponds to multiple user IDs.
const contactsTable = `
  id           INT PRIMARY KEY AUTO_INCREMENT,
  contact_hash CHAR(80),
  uuid         CHAR(36),
  FOREIGN KEY (uuid) REFERENCES auth_users(uuid)
`

// setupDB sets up the auth plugin database tables.
func (p *authp) setupDB() error {
	var tables = []struct {
		name  string
		table string
	}{
		{
			name:  "auth_users",
			table: usersTable,
		},
		{
			name:  "auth_groups",
			table: groupsTable,
		},
		{
			name:  "auth_contacts",
			table: contactsTable,
		},
	}
	for _, v := range tables {
		q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v);`, v.name, v.table)
		_, err := p.db.Exec(q)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// TODO Setup the version record

	return nil
}

func (p *authp) insertUser(tx *sql.Tx, u user) error {
	e, err := encryptUser(u)
	if err != nil {
		return err
	}

	q := "INSERT INTO auth_users VALUES(?, ?, ?, ?);"
	_, err = tx.Exec(q, u.ID, u.Username, u.CreatedAt, e)
	if err != nil {
		return errors.WithStack(err)
	}

	// TODO update groupsTable
	// TODO update contactsTable

	log.Debugf("User inserted into database %v", &u)

	return nil
}

func (p *authp) updateUser(tx *sql.Tx, u user) error {
	e, err := encryptUser(u)
	if err != nil {
		return err
	}

	q := `UPDATE auth_users
        SET username = ?, encrypted = ?
        WHERE uuid = ?;`
	_, err = tx.Exec(q, u.Username, e, u.ID)
	if err != nil {
		return errors.WithStack(err)
	}

	// TODO update groupsTable
	// TODO update contactsTable

	return nil
}

// A errNotFound error is returned if a user is not found.
func (p *authp) getUser(q querier, userID string) (*user, error) {
	var b []byte
	qs := `SELECT encrypted FROM auth_users WHERE uuid = ?;`
	err := q.QueryRow(qs, userID).Scan(&b)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errNotFound
		}
		return nil, errors.WithStack(err)
	}
	u, err := decryptUser(b)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// A errNotFound error is returned if a user is not found.
func (p *authp) getUserByUsername(q querier, username string) (*user, error) {
	var b []byte
	qs := `SELECT encrypted FROM auth_users WHERE username = ?;`
	err := q.QueryRow(qs, username).Scan(&b)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errNotFound
		}
		return nil, errors.WithStack(err)
	}
	u, err := decryptUser(b)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// TODO encrypt blob
func encryptUser(u user) ([]byte, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// TODO decrypt blob
func decryptUser(b []byte) (*user, error) {
	var u user
	err := json.Unmarshal(b, &u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const (
	// timeoutOp is the timeout for a single database operation.
	timeoutOp = 1 * time.Minute
)

// ctxForOp returns a context and cancel function for a single database
// operation.
func ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutOp)
}
