// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

func hasExpired(session *sessions.Session) (bool, error) {
	createdAt, ok := session.Values[sessionValueCreatedAt].(int64)
	if !ok {
		return false, fmt.Errorf("no created_at timestamp found")
	}
	expiresAt := createdAt + int64(session.Options.MaxAge)
	return time.Now().Unix() > expiresAt, nil
}

// getSession returns the active cookie session. If no active cookie session
// exists then a new session object is returned. Access IsNew on the session to
// check if it is an existing session or a new one. The new session will also
// not have any sessions values set, such as user_id, and has not been saved to
// the session store yet.
func (p *politeiawww) getSession(r *http.Request) (*sessions.Session, error) {
	return p.sessions.Get(r, www.CookieSession)
}

// getSessionUserID returns the uuid address of the currently logged in user
// from the session store.
func (p *politeiawww) getSessionUserID(w http.ResponseWriter, r *http.Request) (string, error) {
	session, err := p.getSession(r)
	if err != nil {
		return "", err
	}
	if session.IsNew {
		return "", errSessionNotFound
	}

	// Delete the session if its expired. Setting the MaxAge
	// to <= 0 and then saving it will trigger a deletion.
	obsolete, err := hasExpired(session)
	if err != nil || obsolete {
		session.Options.MaxAge = -1
		p.sessions.Save(r, w, session)
		return "", errSessionNotFound
	}

	return session.Values[sessionValueUserID].(string), nil
}

// getSessionUser retrieves the current session user from the database.
func (p *politeiawww) getSessionUser(w http.ResponseWriter, r *http.Request) (*user.User, error) {
	uid, err := p.getSessionUserID(w, r)
	if err != nil {
		return nil, err
	}

	log.Tracef("getSessionUser: %v", uid)
	pid, err := uuid.Parse(uid)
	if err != nil {
		return nil, err
	}

	user, err := p.db.UserGetById(pid)
	if err != nil {
		return nil, err
	}

	if user.Deactivated {
		p.removeSession(w, r)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNotLoggedIn,
		}
	}

	return user, nil
}

func (p *politeiawww) getSessionID(r *http.Request) string {
	session, err := p.getSession(r)
	if err != nil {
		return ""
	}

	return session.ID
}

// removeSession deletes the session from the database.
func (p *politeiawww) removeSession(w http.ResponseWriter, r *http.Request) error {
	log.Tracef("removeSession")

	session, err := p.getSession(r)
	if err != nil {
		return err
	}

	log.Debugf("Deleting user session: %v %v",
		session.ID, session.Values[sessionValueUserID])

	// Saving the session with a negative MaxAge will cause it to be deleted.
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

// initSession adds a session record to the database and links it to the given
// user ID.
func (p *politeiawww) initSession(w http.ResponseWriter, r *http.Request, userID string) error {
	log.Tracef("initSession: %v", userID)

	session, err := p.getSession(r)
	if err != nil {
		return err
	}
	if !session.IsNew {
		return fmt.Errorf("session already exists")
	}

	session.Values[sessionValueCreatedAt] = time.Now().Unix()
	session.Values[sessionValueUserID] = userID

	return session.Save(r, w)
}
