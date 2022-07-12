// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import app "github.com/decred/politeia/politeiawww/app/v1"

// authmanager.go contains the methods that satisfy the app/v1 AuthManager
// interface.

var (
	_ app.AuthManager = (*auth)(nil)
)

// SetCmdPerms sets the user permission levels for a list of commands.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *auth) SetCmdPerms(perms []app.CmdPerm) error {
	return nil
}

// SessionUserID returns the user ID from the session values if one exists.
// An empty string is returned if a user ID does not exist.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *auth) SessionUserID(as app.Session) string {
	s := newSession(&as)
	return s.UserID()
}

// Authorize checks if the user is authorized to execute a plugin command.
// This includes verifying that the user session is still valid and that the
// user has the correct permissions to execute the command.
//
// Any changes made to the Session will be persisted by the politeia backend.
// It is the responsibility of this method to set the del field of the Session
// to true if the session has expired and should be deleted.
//
// A UserErr is returned if the user is not authorized.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *auth) Authorize(a app.AuthorizeArgs) error {

	return nil
}
