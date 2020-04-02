// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"net/http"
	"time"

	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

const (
	sessionMaxAge = 86400 // One day

	// Session value keys. A user session contains a map that is used
	// for application specific values. The following is a list of the
	// keys for the politeiawww specific values.
	sessionValueUserID    = "user_id"
	sessionValueCreatedAt = "created_at"
)

var (
	// errSessionNotFound is emitted when a session is not found in the
	// session store.
	errSessionNotFound = errors.New("session not found")
)

func sessionIsExpired(session *sessions.Session) bool {
	createdAt := session.Values[sessionValueCreatedAt].(int64)
	expiresAt := createdAt + int64(session.Options.MaxAge)
	return time.Now().Unix() > expiresAt
}

// getSession returns the Session for the session ID from the given http
// request cookie. If no session exists then a new session object is returned.
// Access IsNew on the session to check if it is an existing session or a new
// one. The new session will not have any sessions values set, such as user_id,
// and will not have been saved to the session store yet.
func (p *politeiawww) getSession(r *http.Request) (*sessions.Session, error) {
	return p.sessions.Get(r, www.CookieSession)
}

// getSessionUserID returns the user ID of the user for the given session. A
// errSessionNotFound error is returned if a user session does not exist or
// has expired.
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
	if sessionIsExpired(session) {
		session.Options.MaxAge = -1
		p.sessions.Save(r, w, session)
		return "", errSessionNotFound
	}

	return session.Values[sessionValueUserID].(string), nil
}

// getSessionUser returns the User for the given session. A errSessionFound
// error is returned if a user session does not exist or has expired.
func (p *politeiawww) getSessionUser(w http.ResponseWriter, r *http.Request) (*user.User, error) {
	log.Tracef("getSessionUser")

	uid, err := p.getSessionUserID(w, r)
	if err != nil {
		return nil, err
	}

	pid, err := uuid.Parse(uid)
	if err != nil {
		return nil, err
	}

	user, err := p.db.UserGetById(pid)
	if err != nil {
		return nil, err
	}

	if user.Deactivated {
		err := p.removeSession(w, r)
		if err != nil {
			return nil, err
		}
		return nil, errSessionNotFound
	}

	return user, nil
}

// removeSession removes the given session from the session store.
func (p *politeiawww) removeSession(w http.ResponseWriter, r *http.Request) error {
	log.Tracef("removeSession")

	session, err := p.getSession(r)
	if err != nil {
		return err
	}
	if session.IsNew {
		return errSessionNotFound
	}

	log.Debugf("Deleting user session: %v %v",
		session.ID, session.Values[sessionValueUserID])

	// Saving the session with a negative MaxAge will cause it to be
	// deleted.
	session.Options.MaxAge = -1
	return p.sessions.Save(r, w, session)
}

// initSession creates a new session, adds it to the given http response
// session cookie, and saves it to the session store. If the http request
// already contains a session cookie then the session values will be updated
// and the session will be updated in the session store.
func (p *politeiawww) initSession(w http.ResponseWriter, r *http.Request, userID string) error {
	log.Tracef("initSession: %v", userID)

	// Init session
	session, err := p.getSession(r)
	if err != nil {
		return err
	}

	// Update session with politeiawww specific values
	session.Values[sessionValueCreatedAt] = time.Now().Unix()
	session.Values[sessionValueUserID] = userID

	// Update session in the store and update the response cookie
	return p.sessions.Save(r, w, session)
}
