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
	usersTableName = "auth_users"
	permsTableName = "auth_perms"
)

// usersTable is the database table for user data.
const usersTable = `
  id             CHAR(36) PRIMARY KEY,
  username       VARCHAR(64) NOT NULL UNIQUE,
	encrypted_blob LONGBLOB
`

// permsTable is the database table for user permissions.
const permsTable = `
	user_id CHAR(36),
  FOREIGN KEY (user_id) REFERENCES auth_users(id)
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
			name:  permsTableName,
			table: permsTable,
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
