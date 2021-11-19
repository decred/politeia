// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// Authorizer provides user authorization for plugin commands.
//
// Any changes made to the Session or User during method execution will be
// persisted by the caller.
type Authorizer interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// Authorize checks if the user is authorized to execute a plugin command.
	//
	// A UserError is returned if the user is not authorized.
	Authorize(AuthorizeArgs) error
}

// AuthorizeArgs contains the arguments for the Authorize method.
type AuthorizeArgs struct {
	Session  *Session
	User     *User
	PluginID string
	Version  uint32 // Plugin API version
	Cmd      string
}

// Session contains the data that is saved as part of a user session.
//
// Plugins do not have direct access to the sessions database, but the
// Authorizer plugin is able to update fields on this session struct. Updates
// are saved to the sessions database by the backend.
type Session struct {
	UserID    string
	CreatedAt int64

	// Delete can be set by the Authorizer plugin to instruct the backend to
	// delete the session.
	Delete bool
}
