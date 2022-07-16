// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/json"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
)

// authmanager.go contains the methods that satisfy the app/v1 AuthManager
// interface.

var (
	_ app.AuthManager = (*plugin)(nil)
)

// SetPerms sets the user permission levels for a list of commands.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *plugin) SetCmdPerms(perms []app.CmdPerm) {
	for _, v := range perms {
		p.setPerm(v)
	}
}

// SessionUserID returns the user ID from the session values if one exists.
// An empty string is returned if a user ID does not exist.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *plugin) SessionUserID(as app.Session) string {
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
func (p *plugin) Authorize(a app.AuthorizeArgs) error {
	s := newSession(a.Session)

	// Check if the session has expired. Sessions that
	// have expired will have their del field set to
	// true. We don't return here because the command
	// might be a public command.
	if s.IsLoggedIn() && s.IsExpired(p.sessionMaxAge) {
		s.SetDel()
	}

	// Check if the command is a public command
	if p.cmdIsAllowed(a.Cmd, v1.PermPublic) {
		// The command is a public command, which
		// means we don't need to validate any
		// session data. Execution of the command
		// is allowed.
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
		return app.UserErr{
			Code:    uint32(v1.ErrCodeNotAuthorized),
			Context: "the session has expired",
		}
	}

	// Check the user permissions levels
	var u user
	err := json.Unmarshal(a.User.Data(), &u)
	if err != nil {
		return err
	}
	var isAllowed bool
	for _, permLevel := range u.Perms {
		if p.cmdIsAllowed(a.Cmd, permLevel) {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		return app.UserErr{
			Code:    uint32(v1.ErrCodeNotAuthorized),
			Context: "the user does not have the correct permissions",
		}
	}

	// The user is allowed to execute this command
	return nil
}

// setPerm sets a permission level for a command.
func (p *plugin) setPerm(cp app.CmdPerm) {
	c := cp.Cmd.String()
	permLevels, ok := p.perms[c]
	if !ok {
		permLevels = make(map[string]struct{}, 64)
	}
	for _, v := range cp.Levels {
		permLevels[v] = struct{}{}
	}
	p.perms[c] = permLevels
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
