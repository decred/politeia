// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")
)

type User struct {
	Email    string // User name
	Password string // Password salt+hash
}

type Database interface {
	// Create new proposal
	UserGet(string) (*User, error)

	// Close performs cleanup of the backend.
	Close()
}
