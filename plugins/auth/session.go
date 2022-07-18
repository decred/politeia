// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"time"

	"github.com/decred/politeia/app"
)

const (
	// The following entries are the keys for the key-value session data.
	// The session data is saved to the sessions database by the politeia
	// server. The auth plugin does not need to worry about persisting it.
	sessionKeyUserID    = "user_id"
	sessionKeyCreatedAt = "created_at"
)

// session represents an auth plugin user session.
type session struct {
	// app contains the app session. Any updates made to the app session are
	// saved to the sessions database by the backend.
	app *app.Session

	// The following fields are the auth plugin session values. These values
	// travel in the app.Session values as interface{} types and are type casted
	// when we need to work with them locally. Any updates made to these values
	// are also made to the app.Session values.
	userID    string
	createdAt int64 // Unix timestamp

	// del indicates whether the backend should delete the session from the
	// sessions database.
	del bool
}

// newSession returns a new auth plugin session.
func newSession(s *app.Session) session {
	// The interface{} values need to be type casted
	values := s.Values()
	return session{
		app:       s,
		userID:    values[sessionKeyUserID].(string),
		createdAt: values[sessionKeyCreatedAt].(int64),
	}
}

// SetUserID sets the user ID session value.
func (s *session) SetUserID(userID string) {
	s.userID = userID
	s.app.SetValue(sessionKeyUserID, userID)
}

// UserID returns the user ID session value.
func (s *session) UserID() string {
	return s.userID
}

// SetCreatedAt sets the created at session value.
func (s *session) SetCreatedAt(timestamp int64) {
	s.createdAt = timestamp
	s.app.SetValue(sessionKeyCreatedAt, timestamp)
}

// IsLoggedIn returns whether the session corresponds to a logged in user.
func (s *session) IsLoggedIn() bool {
	return s.userID != ""
}

// IsExpired returns whether the session has expired.
func (s *session) IsExpired(maxAge int64) bool {
	return time.Now().Unix() > s.createdAt+maxAge
}

// SetDel sets the del field to true, indicating that the session should be
// deleted from the sessions database.
func (s *session) SetDel() {
	s.del = true
	s.app.SetDel()
}

// Del returns the del value.
func (s *session) Del() bool {
	return s.del
}
