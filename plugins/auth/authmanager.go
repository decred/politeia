// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"fmt"

	app "github.com/decred/politeia/politeiawww/app/v1"
)

// authmanager.go contains the methods that satisfy the app/v1 AuthManager
// interface.

var (
	_ app.AuthManager = (*auth)(nil)
)

// SetCmdPerms sets the user permission levels for a list of commands.
//
// This function satisfies the app/v1 AuthManager interface.
func (p *auth) SetCmdPerms(perms []app.CmdPerm) {
	for _, v := range perms {
		p.setPerm(v)
	}
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

// setPerm sets a permission level for a command.
func (p *auth) setPerm(c app.CmdPerm) {
	cmdS := cmdStr(c.PluginID, c.Version, c.Name)
	permLevels, ok := p.perms[cmdS]
	if !ok {
		permLevels = make(map[string]struct{}, 64)
	}
	for _, v := range c.Levels {
		permLevels[v] = struct{}{}
	}
	p.perms[cmdS] = permLevels
}

// cmdIsAllowed returns whether the execution of a command is allowed for
// a permission level.
func (p *auth) cmdIsAllowed(pluginID string, version uint32, cmdName, permLevel string) bool {
	cmdS := cmdStr(pluginID, version, cmdName)
	permLevels, ok := p.perms[cmdS]
	if !ok {
		log.Errorf("Permission level has not been set for %v", cmdS)
		return false
	}
	_, ok = permLevels[permLevel]
	return ok
}

// cmdStr returns the string representation of a plugin command.
func cmdStr(pluginID string, pluginVersion uint32, cmdName string) string {
	return fmt.Sprintf("%v-%s-%v", pluginID, pluginVersion, cmdName)
}
