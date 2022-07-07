// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// Session contains a user session.
//
// Plugins do not have direct access to the sessions database, but they can
// update session values during command execution. Updates are saved to the
// sessions database by the backend on successful completion of the plugin
// command.
type Session struct {
	userID    string
	createdAt int64 // Unix timestamp

	// updated represents whether any of the session values have been updated
	// during plugin command execution.
	updated bool

	// del instructs the backend to delete the session.
	del bool
}

// NewSession returns a new Session.
func NewSession(userID string, createdAt int64) *Session {
	return &Session{
		userID:    userID,
		createdAt: createdAt,
	}
}

// SetUserID sets the user ID session value.
func (s *Session) SetUserID(userID string) {
	s.userID = userID
	s.updated = true
}

// UserID returns the user ID session value.
func (s *Session) UserID() string {
	return s.userID
}

// SetCreatedAt sets the created at session value.
func (s *Session) SetCreatedAt(t int64) {
	s.createdAt = t
	s.updated = true
}

// CreatedAt returns the created at session value.
func (s *Session) CreatedAt() int64 {
	return s.createdAt
}

// Updated returns whether the session values have been updated during plugin
// command execution.
func (s *Session) Updated() bool {
	return s.updated
}

// SetDel sets the del field to true, instructing the backend to delete the
// session.
func (s *Session) SetDel() {
	s.del = true
}

// Del returns whether the session should be deleted.
func (s *Session) Del() bool {
	return s.del
}
