// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

// Session contains the values for a user session.
//
// Plugins do not have direct access to the sessions database, but they can
// update session values during command execution. Updates are saved to the
// sessions database by the politeia server on successful completion of the
// plugin command.
type Session struct {
	values map[interface{}]interface{}

	// updated represents whether any of the session values have been updated
	// during plugin command execution. If updated is set to true, the politeia
	// server will save the changes to the sessions database.
	updated bool

	// del instructs the backend to delete the session.
	del bool
}

// NewSession returns a new Session.
func NewSession(values map[interface{}]interface{}) *Session {
	if values == nil {
		values = make(map[interface{}]interface{})
	}
	return &Session{
		values: values,
	}
}

// SetValue sets a session value.
func (s *Session) SetValue(key, value interface{}) {
	s.values[key] = value
	s.updated = true
}

// Values returns a copy of the session values.
func (s *Session) Values() map[interface{}]interface{} {
	c := make(map[interface{}]interface{}, len(s.values))
	for k, v := range s.values {
		c[k] = v
	}
	return c
}

// Updated returns whether the session values have been updated.
func (s *Session) Updated() bool {
	return s.updated
}

// SetDel sets the del field to true, instructing the politeia server to delete
// the session from the database.
func (s *Session) SetDel() {
	s.del = true
}

// Del returns whether the session should be deleted.
func (s *Session) Del() bool {
	return s.del
}
