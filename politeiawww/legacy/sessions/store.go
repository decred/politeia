// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sessions

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"

	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var (
	_ sessions.Store = (*sessionStore)(nil)
)

// sessionStore is a session store backed by the user database.
//
// sessionStore impelements the sessions.Store interface.
type sessionStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	db      user.Database
}

// newSessionID returns a new session ID. A session ID is defined as a 32 byte
// base32 string with padding. The session ID is set by the store and can be
// whatever the store chooses. This ID was chosen simply because it's what the
// gorilla/sesssions package reference implemenation uses.
func newSessionID() string {
	return base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
}

// Get returns a session for the given name after adding it to the registry.
//
// A new session is returned if the given session doesn't exist. Access IsNew
// on the session to check if it is an existing session or a new one. The new
// session will not have any sessions values set and will not have been saved
// to the session store yet.
//
// Get returns a new session and an error if the session exists but could not
// be decoded.
//
// This function satisfies the sessions.Store interface.
func (s *sessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	log.Tracef("SessionStore Get: %v", name)

	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The sessions.Store interface dictates that New() should never return a nil
// session, even in the case of an error if using the Registry infrastructure
// to cache the session.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
//
// This function satisfies the sessions.Store interface.
func (s *sessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	log.Tracef("SessionStore New: %v", name)

	// Setup new session
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	session.ID = newSessionID()

	// Check if the session cookie already exists
	c, err := r.Cookie(name)
	if errors.Is(err, http.ErrNoCookie) {
		log.Tracef("Session cookie not found; returning a new session")
		return session, nil
	} else if err != nil {
		return session, err
	}

	// Session cookie already exists. The encoded session ID travels in
	// the cookie. Decode it and use it to check if the session exists
	// in the store.

	// Decode session ID (overwrites existing session ID)
	err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
	if err != nil {
		// If there are any issues decoding the session ID, the existing
		// session is considered invalid and the newly created session is
		// returned.
		log.Tracef("Decode session: %v", err)
		log.Tracef("Session invalid; returning a new one")
		return session, nil
	}

	// Check if session exists in the store
	userSession, err := s.db.SessionGetByID(session.ID)
	switch err {
	case nil:
		// Session found in database. Decode database session values into
		// the session being returned.
		session.IsNew = false
		err = securecookie.DecodeMulti(session.Name(), userSession.Values,
			&session.Values, s.Codecs...)
		if err != nil {
			return session, err
		}
		log.Tracef("Session found %v", session.ID)
	case user.ErrSessionNotFound:
		// Session not found in database; no action needed since the new
		// session will be returned.
		log.Tracef("Session not found; returning new session")
	default:
		return session, err
	}

	return session, nil
}

// Save saves the session to the store and updates the http response cookie
// with the encoded session ID.
//
// If the Options.MaxAge of the session is <= 0 then the session will be
// deleted from the database. With this process it enforces proper session
// cookie handling so no need to trust in the cookie management in the web
// browser.
//
// This function satisfies the sessions.Store interface.
func (s *sessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	log.Tracef("SessionStore Save: %v", session.ID)

	// Delete session if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		err := s.db.SessionDeleteByID(session.ID)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	// Save session to the store
	id, ok := session.Values[sessionValueUserID].(string)
	if !ok {
		return fmt.Errorf("session value %v not found",
			sessionValueUserID)
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	createdAt, ok := session.Values[sessionValueCreatedAt].(int64)
	if !ok {
		return fmt.Errorf("session value %v not found",
			sessionValueCreatedAt)
	}
	encodedValues, err := securecookie.EncodeMulti(session.Name(),
		session.Values, s.Codecs...)
	if err != nil {
		return err
	}
	err = s.db.SessionSave(user.Session{
		ID:        session.ID,
		UserID:    uid,
		CreatedAt: createdAt,
		Values:    encodedValues,
	})
	if err != nil {
		return err
	}

	// Update session cookie with encoded session ID
	encodedID, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	c := sessions.NewCookie(session.Name(), encodedID, session.Options)
	http.SetCookie(w, c)

	return nil
}

// new returns a new sessionStore.
//
// Keys are defined in pairs to allow key rotation, but the common case is
// to set a single authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for
// encryption. The encryption key can be set to nil or omitted in the last
// pair, but the authentication key is required in all pairs.
//
// It is recommended to use an authentication key with 32 or 64 bytes.
// The encryption key, if set, must be either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256 modes.
func newSessionStore(db user.Database, keyPairs ...[]byte) *sessionStore {
	// Set the maxAge for each securecookie instance
	codecs := securecookie.CodecsFromPairs(keyPairs...)
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(SessionMaxAge)
		}
	}

	return &sessionStore{
		Codecs: codecs,
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   SessionMaxAge, // Max age for the store
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
		db: db,
	}
}
