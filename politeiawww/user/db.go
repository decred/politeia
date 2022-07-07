// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"database/sql"
	"errors"
)

var (
	// ErrNotFound is returned when a user is not found in the database.
	ErrNotFound = errors.New("user not found")
)

// DB represents the user database API.
type DB interface {
	// TxInsert inserts a user into the database using a transaction.
	TxInsert(*sql.Tx, User) error

	// TxUpdate updates a user in the database using a transaction.
	TxUpdate(*sql.Tx, User) error

	// TxGet gets a user from the database using a transactions.
	//
	// An ErrNotFound error is returned if a user is not found for the provided
	// user ID.
	TxGet(tx *sql.Tx, userID string) (*User, error)

	// Get gets a user from the database.
	//
	// An ErrNotFound error is returned if a user is not found for the provided
	// user ID.
	Get(userID string) (*User, error)
}
