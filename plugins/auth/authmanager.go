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
	_ app.AuthManager = (*plugin)(nil)
)

// SetPerms sets the user permission levels for a list of commands.
//
// This function satisfies the app.AuthManager interface.
func (p *plugin) SetCmdPerms(perms []app.CmdPerms) {
	log.Tracef("SetCmdPerms")

	for _, v := range perms {
		p.setPerm(v)
	}
}

// SessionUserID returns the user ID from the session values if one exists.
// An empty string is returned if a user ID does not exist.
//
// This function satisfies the app.AuthManager interface.
func (p *plugin) SessionUserID(as app.Session) string {
	s := newSession(&as)

	log.Tracef("SessionUserID %v", s.UserID())

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
// This function satisfies the app.AuthManager interface.
func (p *plugin) Authorize(a app.AuthorizeArgs) error {
	log.Tracef("Authorize %v", a.Cmds)

	s := newSession(a.Session)

	// Check if the session has expired. Sessions that
	// have expired will have their del field set to
	// true. We don't return here because the command
	// might be a public command.
	if s.IsLoggedIn() && s.IsExpired(p.settings.SessionMaxAge) {
		s.SetDel()
	}

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
		// All of the commands are public.
		// No need to continue.
		return nil
	}

	// Verify that session has not expired and that the
	// user has the correct permissions to execute this
	// command.
	switch {
	case !s.IsLoggedIn():
		// The session does not correspond to a logged in
		// user and the command is not a public command.
		// Execution is not allowed.
		return app.UserErr{
			Code:    uint32(v1.ErrCodeNotAuthorized),
			Context: "the user is not logged in",
		}
	case s.Del():
		// The session has expired
		return app.UserErr{
			Code:    uint32(v1.ErrCodeNotAuthorized),
			Context: "the user is not logged in",
		}
	}

	// Check the user permissions levels
	u, err := p.getUserRO(s.UserID())
	if err != nil {
		return err
	}
	for _, cmd := range a.Cmds {
		var isAllowed bool
		for _, userGroup := range u.Groups {
			if p.cmdIsAllowed(cmd, userGroup) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return app.UserErr{
				Code: uint32(v1.ErrCodeNotAuthorized),
				Context: fmt.Sprintf("the user is not "+
					"authorized to execute %v", cmd.Name),
			}
		}
	}

	// The user is allowed to execute this command
	return nil
}

// setPerm sets a permission level for a command.
func (p *plugin) setPerm(cp app.CmdPerms) {
	c := cp.Cmd.String()
	userGroups, ok := p.perms[c]
	if !ok {
		userGroups = make(map[string]struct{}, 64)
	}
	for _, v := range cp.Groups {
		userGroups[v] = struct{}{}
	}
	p.perms[c] = userGroups
}

// cmdIsAllowed returns whether the execution of a command is allowed for a
// permission level.
func (p *plugin) cmdIsAllowed(c app.CmdDetails, permLevel string) bool {
	permLevels, ok := p.perms[c.String()]
	if !ok {
		log.Errorf("Permission level has not been set for %v", c.String())
		return false
	}
	_, ok = permLevels[permLevel]
	return ok
}
