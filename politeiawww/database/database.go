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

	// ErrUserExists indicates that a user already exists in the database.
	ErrUserExists = errors.New("user already exists")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")
)

// User record.
type User struct {
	Email          string // User email address, also the lookup key.
	HashedPassword []byte // Blowfish hash
	Admin          bool   // Is user an admin
}

type Database interface {
	// User functions
	UserGet(string) (*User, error) // Return user record, key is email
	UserNew(User) error

	// Close performs cleanup of the backend.
	Close()
}
