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

type AuthorizeArgs struct {
	Session  *Session
	User     *User
	PluginID string
	Version  uint32 // Plugin API version
	Cmd      string
}

type Session struct {
	UserID    string
	CreatedAt int64
	Delete    bool
}
