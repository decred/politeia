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

// extractSession extracts and returns the session from the http request
// cookie.
func (p *politeiawww) extractSession(r *http.Request) (*sessions.Session, error) {
	return p.sessions.Get(r, v1.SessionCookieName)
}

// saveUserSession saves the encoded session values to the database and the
// encoded session ID to the response cookie if there were any changes to the
// session. The session is deleted from the database if the plugin sets the
// Deleted field to true.
func (p *politeiawww) saveUserSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, pluginID string, pluginSession *plugin.Session) error {
	// Check if the session should be deleted.
	if pluginSession.Delete {
		s.Options.MaxAge = 0
		return p.sessions.Save(r, w, s)
	}

	// Check if any values were updated.
	var (
		userID    = s.Values[sessionValueUserID].(string)
		createdAt = s.Values[sessionValueUserID].(int64)
	)
	if pluginSession.UserID == userID &&
		pluginSession.CreatedAt == createdAt {
		// No changes were made. There is no
		// need to update the database.
		return nil
	}

	// Update the orignal session object with the changes
	// made by the plugin.
	s.Values[sessionValueUserID] = pluginSession.UserID
	s.Values[sessionValueCreatedAt] = pluginSession.CreatedAt

	// Save the changes to the database.
	return p.sessions.Save(r, w, s)
}

func convertSession(s *sessions.Session) *plugin.Session {
	// The interface{} values need to be type casted.
	var (
		userID    = s.Values[sessionValueUserID].(string)
		createdAt = s.Values[sessionValueUserID].(int64)
	)
	return &plugin.Session{
		UserID:    userID,
		CreatedAt: createdAt,
		Delete:    false,
	}
}
