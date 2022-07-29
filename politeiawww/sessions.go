// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/decred/politeia/app"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	psessions "github.com/decred/politeia/politeiawww/sessions"
	sessionsdb "github.com/decred/politeia/politeiawww/sessions/mysql"
	"github.com/decred/politeia/util"
	"github.com/gorilla/sessions"
)

// setupSessions sets up the politeia sessions store. The provided database
// is used as the backing database for the sessions store.
func (p *politeiawww) setupSessions(db *sql.DB) error {
	cookieKey, err := os.ReadFile(p.cfg.CookieKey)
	if err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return err
		}
		err = os.WriteFile(p.cfg.CookieKey, cookieKey, 0400)
		if err != nil {
			return err
		}
		log.Infof("Cookie key generated")
	}

	sdb, err := sessionsdb.New(db, p.cfg.SessionMaxAge, nil)
	if err != nil {
		return err
	}

	opts := psessions.NewOptions(int(p.cfg.SessionMaxAge))
	p.sessions = psessions.NewStore(sdb, opts, cookieKey)

	return nil
}

// extractSession extracts and returns the session from the http request
// cookie.
func (p *politeiawww) extractSession(r *http.Request) (*sessions.Session, error) {
	s, err := p.sessions.Get(r, v3.SessionCookieName)
	if err != nil {
		return nil, err
	}
	if !s.IsNew {
		log.Debugf("Sesssion %v", s.Values)
	}
	return s, nil
}

// UpdateSession updates a session with any changes that were made during
// execution of a plugin command. The encoded session ID is saved to the
// response cookie and the updated session values are saved to the database.
//
// Session updates occur after plugin commands have already executed. If the
// plugin command executed successfully then the server response must reflect
// this. For this reason, any errors that occur during a session update are
// handled gracefully and logged, rather than returning an error to the user.
func (p *politeiawww) UpdateSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, as *app.Session) {
	err := p.updateSession(r, w, s, as)
	if err != nil {
		log.Errorf("UpdateSession %+v: %v", as, err)
	}
}

// See the UpdateSession function for more details.
func (p *politeiawww) updateSession(r *http.Request, w http.ResponseWriter, s *sessions.Session, as *app.Session) error {
	// Check if the session should be deleted.
	if as.Del() {
		s.Options.MaxAge = 0
		err := p.sessions.Save(r, w, s)
		if err != nil {
			return err
		}

		log.Debugf("Session deleted %v", as.Values())

		return nil
	}

	// Check if any values were updated.
	if !as.Updated() {
		// No updates were made. Nothing else to do.
		return nil
	}

	// Update the orignal session with any changes that
	// were made by the app and save the session to the
	// database.
	s.Values = as.Values()
	err := p.sessions.Save(r, w, s)
	if err != nil {
		return err
	}

	log.Debugf("Session saved %v", as.Values())

	return nil
}