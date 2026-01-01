// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"fmt"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
)

// authmanager.go contains the methods that satisfy the app.AuthManager
// interface.

var (
	_ app.AuthManager = (*authp)(nil)
)

// SessionUserID returns the user ID from the session values if one exists.
// An empty string is returned if a user ID does not exist.
//
// This function satisfies the app.AuthManager interface.
func (p *authp) SessionUserID(as app.Session) string {
	s := newSession(&as)

	log.Tracef("SessionUserID %v", s.UserID())

	return s.UserID()
}

// Authorize checks if the user is authorized to execute a list of plugin
// commands. This includes verifying that the user session is valid and that
// the user has the correct permissions to execute the commands.
//
// Configuring the session max age and checking for expired sessions is handled
// in the server layer. This method does not need to worry about checking for
// exipred sessions. Expired sessions will never make it to the plugin layer.
//
// A UserErr is returned if the user is not authorized to execute one or more
// of the provided commands.
//
// Changes made to the Session are not persisted by the politeia server.
//
// This function satisfies the app.AuthManager interface.
func (p *authp) Authorize(a app.AuthorizeArgs) error {
	log.Tracef("Authorize %v", &a)

	// Check if all of the the commands are public. We
	// don't have to validate the session data or the
	// user permissions if all of the commands are public.
	public := true
	for _, cmd := range a.Cmds {
		if p.cmdIsAllowed(cmd, v1.PublicUser) {
			// The command is public
			continue
		}
		public = false
		break
	}
	if public {
		// All of the commands are public. No need
		// to continue. Execution is allowed.
		return nil
	}

	// Verify that the session user has the correct
	// permissions to execute this command.
	s := newSession(&a.Session)
	if !s.IsLoggedIn() {
		// The session does not correspond to a logged
		// in user and the commands are not public.
		// Execution is not allowed.
		return app.UserErr{
			Code:    uint32(v1.ErrCodeNotAuthorized),
			Context: "the user is not logged in",
		}
	}
	u, err := p.getUser(p.db, s.UserID())
	if err != nil {
		return err
	}
	for _, cmd := range a.Cmds {
		var allowed bool
		for _, userGroup := range u.Groups {
			if !p.cmdIsAllowed(cmd, userGroup) {
				continue
			}
			// The user is part of a group that
			// is allowed to execute this command.
			allowed = true
			break
		}
		if !allowed {
			return app.UserErr{
				Code: uint32(v1.ErrCodeNotAuthorized),
				Context: fmt.Sprintf("the user is not "+
					"authorized to execute %v", &cmd),
			}

			// Check the next command
		}
	}

	// The user is allowed to execute this command
	return nil
}
