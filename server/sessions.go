// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"net/http"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/server/api/v1"
	"github.com/gorilla/sessions"
)

// extractSession extracts and returns the session from the http request
// cookie.
func (s *Server) extractSession(r *http.Request) (*sessions.Session, error) {
	sn, err := s.sessions.Get(r, v1.SessionCookieName)
	if err != nil {
		return nil, err
	}
	if !sn.IsNew {
		log.Debugf("Sesssion %v", sn.Values)
	}
	return sn, nil
}

// updateSession updates a session with any changes that were made during
// execution of a plugin command. The encoded session ID is saved to the
// response cookie and the updated session values are saved to the database.
func (s *Server) updateSession(r *http.Request, w http.ResponseWriter, sn *sessions.Session, asn *app.Session) error {
	// Check if the session should be deleted.
	if asn.Del() {
		sn.Options.MaxAge = 0
		err := s.sessions.Save(r, w, sn)
		if err != nil {
			return err
		}

		log.Debugf("Session deleted %v", asn.Values())

		return nil
	}

	// Check if any values were updated.
	if !asn.Updated() {
		// No updates were made. Nothing else to do.
		return nil
	}

	// Update the orignal session with any changes that
	// were made by the app and save the session to the
	// database.
	sn.Values = asn.Values()
	err := s.sessions.Save(r, w, sn)
	if err != nil {
		return err
	}

	log.Debugf("Session saved %v", asn.Values())

	return nil
}
