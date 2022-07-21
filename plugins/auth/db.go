// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"
	"fmt"

	"github.com/pkg/errors"
)

var (
	// errNotFound is returned when a record is not found in the database.
	errNotFound = errors.New("not found")
)

const (
	// The following fields are the database tables names for the auth plugin.
	// It is best practice to prefix the plugin ID onto the table name.
	//
	// Note: some table names are hard coded into the table definition foreign
	// key constraints.
	usersTableName  = "auth_users"
	groupsTableName = "auth_groups"
)

// usersTable is the database table for user data.
const usersTable = `
  uuid           CHAR(36) PRIMARY KEY,
  username       VARCHAR(64) NOT NULL UNIQUE,
	encrypted_blob LONGBLOB
`

// groupsTable is the database table for user groups. A user can be a part
// of many groups.
const groupsTable = `
	uuid  CHAR(36),
	group VARCHAR(64) NOT NULL
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
func (p *plugin) setupDB() error {
	var tables = []struct {
		name  string
		table string
	}{
		{
			name:  usersTableName,
			table: usersTable,
		},
		{
			name:  groupsTableName,
			table: groupsTable,
		},
	}
	for _, v := range tables {
		q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`, v.name, v.table)
		_, err := p.db.Exec(q)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// TODO Setup the version record

	return nil
}

func (p *plugin) insertUser(tx *sql.Tx, u user) error {
	return nil
}

func (p *plugin) updateUser(tx *sql.Tx, u user) error {
	return nil
}

func (p *plugin) getUser(tx *sql.Tx, userID string) (*user, error) {
	return nil, nil
}

func (p *plugin) getUserByUsername(tx *sql.Tx, username string) (*user, error) {
	return nil, nil
}

func (p *plugin) getUserRO(userID string) (*user, error) {
	return nil, nil
}

func (p *plugin) encrypt(b []byte) ([]byte, error) {
	return nil, nil
}
