// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// AuthManager provides user authorization for plugin commands.
//
// Any changes made to the Session or User during method execution will be
// persisted by the caller.
type AuthManager interface {
	// ID returns the plugin ID.
	ID() string

	// SetCmdPerms sets the user permission levels for a list of commands.
	SetCmdPerms([]CmdPerm) error

	// Authorize checks if the user is authorized to execute a plugin command.
	//
	// A UserErr is returned if the user is not authorized.
	Authorize(AuthorizeArgs) error
}

// CmdPerm represents a user permission level for a plugin command.
type CmdPerm struct {
	PluginID string
	Cmd      string
	Perm     string
}

// AuthorizeArgs contains the arguments for the Authorize method.
type AuthorizeArgs struct {
	Session  *Session
	User     *User
	PluginID string
	Version  uint32 // Plugin API version
	Cmd      string
}
