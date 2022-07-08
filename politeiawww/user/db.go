// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
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

// User represents an app user.
//
// Plugins are only provided with and can only edit the plugin data that they
// own. The user object does not necessarily contain all plugin data for the
// user. Plugins have two ways to save user data:
//
// 1. Update the user object that is provided to them by the app during the
//    execution of plugin commands. These updates are saved to the database by
//    the app. Plugins have the option of saving data to the user object as
//    either clear text or encrypted.
//
// 2. Plugins can create and manage a database table themselves to store
//    plugin user data. This option should be reserved for data that would
//    cause performance issues if saved to this global user object.
type User struct {
	ID      uuid.UUID             // Unique ID
	Plugins map[string]PluginData // [pluginID]PluginData
	Updated bool
}

// PluginData contains the user data for a specific plugin.
type PluginData struct {
	ClearText []byte
	Encrypted []byte
}
