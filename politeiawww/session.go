// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/gorilla/sessions"
)

const (
	// The following entries are the keys for the key-value session data. This
	// data is encoded and saved to the sessions database.
	sessionValueUserID    = "user_id"
	sessionValueCreatedAt = "created_at"
)

// extractSession extracts and returns the session from the http request
// cookie.
func (p *politeiawww) extractSession(r *http.Request) (*sessions.Session, error) {
	return p.sessions.Get(r, v3.SessionCookieName)
}

// updateSession updates a session with any changes that were made during
// execution of a plugin command. The encoded session ID is saved to the
// response cookie and the updated session values are saved to the database.
func (p *politeiawww) updateSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, ps *plugin.Session) error {
	// Check if the session should be deleted.
	if ps.Del() {
		s.Options.MaxAge = 0
		return p.sessions.Save(r, w, s)
	}

	// Check if any values were updated.
	if !ps.Updated() {
		// No updates were made. Nothing else to do.
		return nil
	}

	// Update the orignal session object with the changes
	// made by the plugin.
	s.Values[sessionValueUserID] = ps.UserID()
	s.Values[sessionValueCreatedAt] = ps.CreatedAt()

	// Save the changes to the database.
	return p.sessions.Save(r, w, s)
}

// convertSession converts a session into a plugin session.
func convertSession(s *sessions.Session) *plugin.Session {
	// The interface{} values need to be type casted.
	var (
		userID    = s.Values[sessionValueUserID].(string)
		createdAt = s.Values[sessionValueUserID].(int64)
	)
	return plugin.NewSession(userID, createdAt)
}
