// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sessions

import "errors"

var (
	// ErrNotFound is returned when an entry is not found in the database.
	ErrNotFound = errors.New("session not found")
)

// DB represents the database for encoded session data.
type DB interface {
	// Save saves a session to the database.
	Save(sessionID string, s EncodedSession) error

	// Del deletes a session from the database.
	//
	// An error is not returned if the session does not exist.
	Del(sessionID string) error

	// Get gets a session from the database.
	//
	// An ErrNotFound error MUST be returned if a session is not found
	// for the session ID.
	Get(sessionID string) (*EncodedSession, error)
}

// EncodedSession contains a session's encoded values.
type EncodedSession struct {
	Values string
}
