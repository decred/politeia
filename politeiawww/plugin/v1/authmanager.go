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

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// SetPermission sets the user permission level for a command.
	SetPermission(pluginID, cmd, permissionLevel string)

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
