// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "github.com/google/uuid"

// User represents an app user.
type User struct {
	ID uuid.UUID // Unique ID

	// data contains the user data that is owned by the plugin. Plugins are not
	// able to directly access data that they do not own.
	//
	// This field can be updated by the plugin during execution of write
	// commands. Updates are persisted by the app on successful completion of
	// the plugin command. Any updates made during the execution of read-only
	// commands are ignored.
	//
	// Plugin data is encrypted by the database layer prior to being saved.
	// Plugins do not need to worry about encrypting or decrypting this data.
	// The data will always be provided to the plugin as clear text.
	data    []byte
	updated bool
}

// NewUser returns a new User.
func NewUser(id uuid.UUID, data []byte) *User {
	return &User{
		ID:   id,
		data: data,
	}
}

// SetData sets the plugin data.
func (u *User) Set(data []byte) {
	u.data = data
	u.updated = true
}

// Data returns the plugin data.
func (u *User) Data() []byte {
	return u.data
}

// Updated returns whether the plugin data has been updated.
func (u *User) Updated() bool {
	return u.updated
}
