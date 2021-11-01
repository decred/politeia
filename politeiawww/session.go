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

	// Get the user from the database
	u, err := p.userDB.Get(userID)
	if err != nil {
		return nil, nil, err
	}

	return s, u, nil
}

// saveUserSession saves the encoded session values to the database and the
// encoded session ID to the response cookie if the provided plugin made an
// update to the user's session.
func (p *politeiawww) saveUserSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, usr *plugin.User, pluginID string) error {
	if !usr.Session.Updated() {
		// No session values were updated.
		// Nothing needs to be saved.
		return nil
	}

	// Update the orignal session object with
	// the changes made by the plugin.
	s.Values[pluginID] = usr.Session.Value()

	return p.sessions.Save(r, w, s)
}
