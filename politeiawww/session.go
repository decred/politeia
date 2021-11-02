// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/gorilla/sessions"
)

const (
	sessionValueUserID    = "user-id"
	sessionValueCreatedAt = "created-at"
)

// extractSession extracts the session from the http request. The session and
// the user ID for the session, if one exists, is returned.
func (p *politeiawww) extractSession(r *http.Request) (*sessions.Session, string, error) {
	// Get the session from the request cookie
	s, err := p.sessions.Get(r, v1.SessionCookieName)
	if err != nil {
		return nil, "", err
	}

	// Pull the user ID out of the session values. This
	// will only exist if the client making the request
	// is a logged in user.
	userID := s.Values[sessionValueUserID].(string)
	return s, userID, nil
}

// saveUserSession saves the encoded session values to the database and the
// encoded session ID to the response cookie if the provided plugin made an
// update to the user's session.
func (p *politeiawww) saveUserSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, pluginID string, pluginSession *plugin.Session) error {
	if !pluginSession.Updated() {
		// No session values were updated.
		// Nothing needs to be saved.
		return nil
	}

	// Update the orignal session object with
	// the changes made by the plugin.
	s.Values[pluginID] = pluginSession.Value()

	// Save the changes to the database
	return p.sessions.Save(r, w, s)
}
