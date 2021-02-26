// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sessions

import (
	"errors"
	"net/http"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

const (
	// SessionMaxAge is the max age for a session in seconds.
	SessionMaxAge = 86400 // One day

	// Session value keys. A user session contains a map that is used
	// for application specific values. The following is a list of the
	// keys for the politeiawww specific values.
	sessionValueUserID    = "user_id"
	sessionValueCreatedAt = "created_at"
)

var (
	// ErrSessionNotFound is emitted when a session is not found in the
	// session store.
	ErrSessionNotFound = errors.New("session not found")
)

// Sessions manages politeiawww sessions.
type Sessions struct {
	store  sessions.Store
	userdb user.Database
}

func sessionIsExpired(session *sessions.Session) bool {
	createdAt := session.Values[sessionValueCreatedAt].(int64)
	expiresAt := createdAt + int64(session.Options.MaxAge)
	return time.Now().Unix() > expiresAt
}

// GetSession returns the Session for the session ID from the given http
// request cookie. If no session exists then a new session object is returned.
// Access IsNew on the session to check if it is an existing session or a new
// one. The new session will not have any sessions values set, such as user_id,
// and will not have been saved to the session store yet.
func (s *Sessions) GetSession(r *http.Request) (*sessions.Session, error) {
	log.Tracef("GetSession")

	return s.store.Get(r, www.CookieSession)
}

// GetSessionUserID returns the user ID of the user for the given session. A
// ErrSessionNotFound error is returned if a user session does not exist or
// has expired.
func (s *Sessions) GetSessionUserID(w http.ResponseWriter, r *http.Request) (string, error) {
	log.Tracef("GetSessionUserID")

	session, err := s.GetSession(r)
	if err != nil {
		return "", err
	}
	if session.IsNew {
		// If the session is new it means the request did not contain a
		// valid session. This could be because it was expired or it
		// did not exist.
		log.Debugf("Session not found for user")
		return "", ErrSessionNotFound
	}

	// Delete the session if its expired. Setting the MaxAge to <= 0
	// and saving the session will trigger a deletion. The previous
	// GetSession call should already filter out expired sessions so
	// this is really just a sanity check.
	if sessionIsExpired(session) {
		log.Debug("Session is expired")
		session.Options.MaxAge = -1
		s.store.Save(r, w, session)
		return "", ErrSessionNotFound
	}

	return session.Values[sessionValueUserID].(string), nil
}

// GetSessionUser returns the User for the given session. A errSessionFound
// error is returned if a user session does not exist or has expired.
func (s *Sessions) GetSessionUser(w http.ResponseWriter, r *http.Request) (*user.User, error) {
	log.Tracef("GetSessionUser")

	uid, err := s.GetSessionUserID(w, r)
	if err != nil {
		return nil, err
	}

	pid, err := uuid.Parse(uid)
	if err != nil {
		return nil, err
	}

	user, err := s.userdb.UserGetById(pid)
	if err != nil {
		return nil, err
	}

	if user.Deactivated {
		log.Debugf("User has been deactivated")
		err := s.DelSession(w, r)
		if err != nil {
			return nil, err
		}
		return nil, ErrSessionNotFound
	}

	log.Debugf("Session found for user %v", user.ID)

	return user, nil
}

// DelSession removes the given session from the session store.
func (s *Sessions) DelSession(w http.ResponseWriter, r *http.Request) error {
	log.Tracef("DelSession")

	session, err := s.GetSession(r)
	if err != nil {
		return err
	}
	if session.IsNew {
		return ErrSessionNotFound
	}

	log.Debugf("Deleting user session %v", session.Values[sessionValueUserID])

	// Saving the session with a negative MaxAge will cause it to be
	// deleted.
	session.Options.MaxAge = -1
	return s.store.Save(r, w, session)
}

// NewSession creates a new session, adds it to the given http response
// session cookie, and saves it to the session store. If the http request
// already contains a session cookie then the session values will be updated
// and the session will be updated in the session store.
func (s *Sessions) NewSession(w http.ResponseWriter, r *http.Request, userID string) error {
	log.Tracef("NewSession: %v", userID)

	// Init session
	session, err := s.GetSession(r)
	if err != nil {
		return err
	}

	// Update session with politeiawww specific values
	session.Values[sessionValueCreatedAt] = time.Now().Unix()
	session.Values[sessionValueUserID] = userID

	log.Debugf("Session created for user %v", userID)

	// Update session in the store and update the response cookie
	return s.store.Save(r, w, session)
}

// New returns a new Sessions context.
func New(userdb user.Database, keyPairs ...[]byte) *Sessions {
	return &Sessions{
		store:  newSessionStore(userdb, keyPairs...),
		userdb: userdb,
	}
}
