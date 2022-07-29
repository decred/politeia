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
}

// usersTable is the database table for user data.
const usersTable = `
  uuid           CHAR(36) PRIMARY KEY,
  username       VARCHAR(64) NOT NULL UNIQUE,
	encrypted_blob LONGBLOB
`

// groupsTable is the database table for user groups. A user can be a part
// of many groups.
const groupsTable = `
	uuid       CHAR(36),
	user_group VARCHAR(64) NOT NULL,
  FOREIGN KEY (uuid) REFERENCES auth_users(uuid)
`

// contactsTable is a database table that is used to lookup a user ID based
// on their contact information.
//
// For example, a user that wishes to reset their password can do so by
// providing the email address for the account. This table allows us to lookup
// the user ID using the email address.
//
// The primary key is a base64 encoded bcyrpt hash of the contact information.
// It's hashed using bcrypt to add a layer of protection in the event that the
// database is compromised.
//
// user_ids contains a JSON encoded []string, where each entry is a user ID.
// Contact information is not required to be unique, so it's possible that a
// contact, such as an email address, corresponds to multiple user IDs.
const contactsTable = `
  contact_hash CHAR(80) PRIMARY KEY,
	user_ids     BLOB NOT NULL
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

	q := "INSERT INTO auth_users VALUES(?, ?, ?);"
	_, err = tx.Exec(q, u.ID, u.Username, e)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, group := range u.Groups {
		q = "INSERT INTO auth_groups VALUES(?, ?);"
		_, err = tx.Exec(q, u.ID, group)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// TODO update contactsTable

	log.Debugf("User inserted into database %v", &u)

	return nil
}

// A errNotFound error is returned if a user is not found.
func (p *authp) updateUser(tx *sql.Tx, u user) error {
	return nil
}

// A errNotFound error is returned if a user is not found.
func (p *authp) getUser(q querier, userID string) (*user, error) {
	qs := `SELECT *
        FROM auth_users u
        INNER JOIN auth_groups USING(uuid)
        WHERE u.uuid=?;`

	rows, err := q.Query(qs, userID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	// Unpack the results
	var (
		username  string
		encrypted []byte
		group     string

		groups    = make([]string, 0, 64)
		rowsCount int
	)
	for rows.Next() {
		err = rows.Scan(&userID, &username, &encrypted, &group)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		groups = append(groups, group)
		rowsCount++
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if rowsCount == 0 {
		return nil, errNotFound
	}

	u := user{
		ID:       userID,
		Username: username,
		Groups:   groups,
	}
	err = decryptUser(encrypted, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// A errNotFound error is returned if a user is not found.
func (p *authp) getUserByUsername(tx *sql.Tx, username string) (*user, error) {
	q := `SELECT *
        FROM auth_users u
        INNER JOIN auth_groups USING(uuid)
        WHERE u.username=?;`

	rows, err := tx.Query(q, username)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	// Unpack the results
	var (
		userID    string
		encrypted []byte
		group     string

		groups    = make([]string, 0, 64)
		rowsCount int
	)
	for rows.Next() {
		err = rows.Scan(&userID, &username, &encrypted, &group)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		groups = append(groups, group)
		rowsCount++
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if rowsCount == 0 {
		return nil, errNotFound
	}

	u := user{
		ID:       userID,
		Username: username,
		Groups:   groups,
	}
	err = decryptUser(encrypted, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// eblob contains the user fields that are saved as an encrypted blob.
type eblob struct {
	Password    []byte        `json:"password"`
	ContactInfo []contactInfo `json:"contactinfo,omitempty"`
}

// TODO encrypt blob
func encryptUser(u user) ([]byte, error) {
	e := eblob{
		Password:    u.Password,
		ContactInfo: u.ContactInfo,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// TODO decrypt blob
func decryptUser(b []byte, u *user) error {
	var e eblob
	err := json.Unmarshal(b, &e)
	if err != nil {
		return nil
	}

	u.Password = e.Password
	u.ContactInfo = e.ContactInfo

	return nil
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
