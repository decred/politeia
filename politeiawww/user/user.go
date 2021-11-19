// Copyright (c) 2021 The Decred developers
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

// User represents a politeia user.
//
// Plugins are only provided with and can only edit the plugin data that they
// own. The user object does not necessarily contain all plugin data for the
// user. Plugins have two ways to save user data:
//
// 1. Update the user object that is provided to them by the backend during the
//    execution of plugin commands. These updates are saved to the database by
//    the backend. Plugins have the option of saving data to the user object as
//    either clear text or encrypted.
//
// 2. Plugins can create and manage a database table themselves to store plugin
//    user data in. This option should be reserved for data that would cause
//    performance issues if saved to this global user object.
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

// DB represents the user database API.
type DB interface {
	// InsertTx inserts a user into the database using a transaction.
	InsertTx(*sql.Tx, User) error

	// UpdateTx updates a user in the database using a transaction.
	UpdateTx(*sql.Tx, User) error

	// GetTx gets a user from the database using a transactions.
	//
	// An ErrNotFound error is returned if a user is not found for the provided
	// user ID.
	GetTx(tx *sql.Tx, userID string) (*User, error)

	// GetTx gets a user from the database.
	//
	// An ErrNotFound error is returned if a user is not found for the provided
	// user ID.
	Get(userID string) (*User, error)
}
