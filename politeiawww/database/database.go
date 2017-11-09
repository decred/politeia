// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates that a user already exists in the database.
	ErrUserExists = errors.New("user already exists")

	// ErrInvalidEmail indicates that a user's email is not properly formatted.
	ErrInvalidEmail = errors.New("invalid user email")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")
)

// Identity wraps an ed25519 public key and timestamps to indicate if it is
// active.  If deactivated != 0 then the key is no longer valid.
type Identity struct {
	Key         [identity.PublicKeySize]byte // ed25519 public key
	Activated   int64                        // Time key as acivated for use
	Deactivated int64                        // Time key was deactivated
}

// User record.
type User struct {
	ID                              uint64 // Unique id
	Email                           string // Email address + lookup key.
	HashedPassword                  []byte // Blowfish hash
	Admin                           bool   // Is user an admin
	NewUserVerificationToken        []byte // Verification token during signup
	NewUserVerificationExpiry       int64  // Verification expiration
	ResetPasswordVerificationToken  []byte // Reset password token
	ResetPasswordVerificationExpiry int64  // Reset password token expiration

	// All dentitiesuser has ever used.  User should only have one
	// active key at a time.  We allow multiples in order to deal with key
	// loss.
	Identities []Identity
}

// Database interface that is required by the web server.
type Database interface {
	// User functions
	UserGet(string) (*User, error) // Return user record, key is email
	UserNew(User) error            // Add new user
	UserUpdate(User) error         // Update existing user

	// Close performs cleanup of the backend.
	Close() error
}
