// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base32"
	"fmt"
	"net/http"
	"strings"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// SessionStore stores sessions in the database.
//
// Please note: this is (by and large) a clone of gorilla mux'
// `sessions.FilesystemStore` with the save(), load() and erase()
// methods adapted to use the database as the backing storage.
type SessionStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	db      user.Database
}

// NewSessionStore returns a new SessionStore.
//
// The db argument is the database where sessions will be saved.
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
func NewSessionStore(db user.Database, keyPairs ...[]byte) *SessionStore {
	ss := &SessionStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   sessionMaxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
		db: db,
	}

	ss.MaxAge(ss.Options.MaxAge)
	return ss
}

// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (s *SessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
func (s *SessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				// Session found in database
				session.IsNew = false
			} else if err == user.ErrSessionDoesNotExist {
				// Session not found in database, return the *new* session
			} else {
				return nil, err
			}
		}
	}
	return session, nil
}

// Save adds a single session to the response.
//
// If the Options.MaxAge of the session is <= 0 then the session file will be
// deleted from the database. With this process it enforces proper session
// cookie handling so no need to trust in the cookie management in the web
// browser.
func (s *SessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		// Because the ID is used in the filename, encode it to
		// use alphanumeric characters only.
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
	}
	if err := s.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *SessionStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// save writes encoded session.Values to the database.
func (s *SessionStore) save(session *sessions.Session) error {
	// get the user for this session
	id, ok := session.Values["user_id"].(string)
	if !ok {
		return fmt.Errorf("no user_id found in session")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}
	us := user.Session{
		ID:     session.ID,
		Values: encoded,
		UserID: uid,
	}

	return s.db.SessionSave(us)
}

// load reads a database record and decodes its content into session.Values.
func (s *SessionStore) load(session *sessions.Session) error {
	us, err := s.db.SessionGetById(session.ID)
	if err != nil {
		return err
	}
	err = securecookie.DecodeMulti(
		session.Name(), us.Values, &session.Values, s.Codecs...)
	if err != nil {
		return err
	}
	return nil
}

// delete removes the database record for the provided session.
func (s *SessionStore) erase(session *sessions.Session) error {
	return s.db.SessionDeleteById(session.ID)
}
