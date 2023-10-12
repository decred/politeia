// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"github.com/decred/politeia/app"
)

const (
	// The following entries are the keys for the key-value session data.
	// The session data is saved to the sessions database by the politeia
	// server. The auth plugin does not need to worry about persisting it.
	sessionKeyUserID = "user_id"
)

// session represents an auth plugin user session.
type session struct {
	// appSession contains the app session. Any updates made to the app session
	// are saved to the sessions database by the politeia server.
	appSession *app.Session

	// The following fields are the auth plugin session values. These values
	// travel in the app.Session values as interface{} types and are type casted
	// when we need to work with them locally. Any updates made to these values
	// are also made to the app.Session values.
	userID string

	// del indicates whether the backend should delete the session from the
	// sessions database.
	del bool
}

// newSession returns a new auth plugin session.
func newSession(s *app.Session) session {
	// The interface{} values need to be type casted
	var (
		values = s.Values()
		userID string
	)
	v, ok := values[sessionKeyUserID]
	if ok {
		userID = v.(string)
	}
	return session{
		appSession: s,
		userID:     userID,
	}
}

// SetUserID sets the user ID session value.
func (s *session) SetUserID(userID string) {
	s.userID = userID
	s.appSession.SetValue(sessionKeyUserID, userID)
}

// UserID returns the user ID session value.
func (s *session) UserID() string {
	return s.userID
}

// IsLoggedIn returns whether the session corresponds to a logged in user.
func (s *session) IsLoggedIn() bool {
	return s.userID != ""
}

// SetDel sets the del field to true, indicating that the session should be
// deleted from the sessions database.
func (s *session) SetDel() {
	s.del = true
	s.appSession.SetDel()
}

// Del returns the del value.
func (s *session) Del() bool {
	return s.del
}
