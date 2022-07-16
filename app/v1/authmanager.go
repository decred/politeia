// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// AuthManager provides user authorization for plugin commands.
type AuthManager interface {
	// ID returns the plugin ID.
	ID() string

	// SetCmdPerms sets the user permission levels for a list of plugin commands.
	// The cmd permissions should be setup during app initialization.
	SetCmdPerms([]CmdPerm)

	// SessionUserID returns the user ID from the session values if one exists.
	// An empty string is returned if a user ID does not exist.
	SessionUserID(Session) string

	// Authorize checks if the user is authorized to execute a plugin command.
	// This includes verifying that the user session is still valid and that the
	// user has the correct permissions to execute the command.
	//
	// Any changes made to the Session will be persisted by the politeia backend.
	// It is the responsibility of this method to set the del field of the
	// Session to true if the session has expired and should be deleted.
	//
	// A UserErr is returned if the user is not authorized.
	Authorize(AuthorizeArgs) error
}

// CmdPerm represents the user permission levels for a plugin command.
type CmdPerm struct {
	Cmd    CmdDetails
	Levels []string // Permission levels
}

// AuthorizeArgs contains the arguments for the Authorize method.
type AuthorizeArgs struct {
	Session *Session
	User    User
	Cmd     CmdDetails
}
