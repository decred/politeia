package main

import (
	"encoding/base32"
	"errors"
	"net/http"
	"strings"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// SessionStore stores sessions in the database.
//
// Please note: this is (by and large) a clone of goriall mux'
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
// See NewCookieStore() for a description of the other parameters.
func NewSessionStore(db user.Database, keyPairs ...[]byte) *SessionStore {
	fs := &SessionStore{
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

	fs.MaxAge(fs.Options.MaxAge)
	return fs
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new SessionStore is 4096.
func (s *SessionStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *SessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name.
//
// See CookieStore.New().
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
				session.IsNew = false
			} else {
				if err == user.ErrSessionDoesNotExist {
					err = nil
				}
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
//
// If the Options.MaxAge of the session is <= 0 then the session file will be
// deleted from the database. With this process it enforces proper session
// cookie handling so no need to trust in the cookie management in the web
// browser.
func (s *SessionStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
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
		return errors.New("no `user_id` found in session")
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

// delete session database record.
func (s *SessionStore) erase(session *sessions.Session) error {
	return s.db.SessionDeleteById(session.ID)
}
