// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/gorilla/sessions"
)

const (
	sessionValueUserID = "userid"
)

func (p *politeiawww) extractSession(r *http.Request) (*sessions.Session, *user.User, error) {
	// Get the session from the request cookie
	s, err := p.sessions.Get(r, v1.SessionCookieName)
	if err != nil {
		return nil, nil, err
	}

	// Check if the session is for a logged in user
	userID := s.Values[sessionValueUserID].(string)
	if userID == "" {
		// Session does not correspond to a logged
		// in user. No need to continue.
		return s, nil, nil
	}

	// Get the user the session
	u, err := p.userDB.Get(userID)
	if err != nil {
		return nil, nil, err
	}

	return s, u, nil
}

// saveSession saves the encoded session values to the database and the encoded
// session ID to the response cookie. This is only performed if there are
// session values that need to be saved.
func (p *politeiawww) saveSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, updatedSession plugin.Session) error {
	if !updatedSession.Updated {
		// No session values were updated.
		// Nothing needs to be saved.
		return nil
	}

	// Update the orignal session object with
	// the changes made by the plugins.
	for k, v := range updatedSession.Values {
		s.Values[k] = v
	}

	return p.sessions.Save(r, w, s)
}

func convertSession(s sessions.Session) plugin.Session {
	values := make(map[string]interface{}, len(s.Values))
	for k, v := range s.Values {
		// Type cast the interface{} key to a string
		values[k.(string)] = v
	}
	return plugin.Session{
		Values: values,
	}
}
