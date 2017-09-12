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
	ID                 uint64 // Unique id
	Email              string // User email address, also the lookup key.
	HashedPassword     []byte // Blowfish hash
	Admin              bool   // Is user an admin
	VerificationToken  []byte // Token used to verify user's email address (if populated).
	VerificationExpiry int64  // Unix time representing the moment that the token expires.
}

// Database interface that is required by the web server.
type Database interface {
	// User functions
	UserGet(string) (*User, error) // Return user record, key is email
	UserNew(User) (uint64, error)  // Add new user
	UserUpdate(User) error         // Update existing user

	// Clears the entire database.
	Clear() error

	// Close performs cleanup of the backend.
	Close()
}
