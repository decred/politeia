// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

import (
	"fmt"
	"strings"
)

// AuthManager provides user authorization for plugin commands.
type AuthManager interface {
	// ID returns the plugin ID.
	ID() string

	// AddUserGroups adds custom user groups to the AuthManager.
	//
	// Custom user groups should be setup by the app during app initialization.
	AddUserGroups([]UserGroup)

	// SetCmdPerms sets the permissions for a list of plugin commands.
	//
	// Command permissions should be setup by the app during app initialization.
	SetCmdPerms([]CmdPerms)

	// SessionUserID returns the user ID from the session values if one exists.
	// An empty string is returned if a user ID does not exist.
	SessionUserID(Session) string

	// Authorize checks if the user is authorized to execute a list of plugin
	// commands. This includes verifying that the user session is valid and that
	// the user has the correct permissions to execute the commands.
	//
	// Configuring the session max age and checking for expired sessions is
	// handled in the server layer. This method does not need to worry about
	// checking for exipred sessions. Expired sessions will never make it to the
	// plugin layer.
	//
	// A UserErr is returned if the user is not authorized to execute one or more
	// of the provided commands.
	//
	// Changes made to the Session are not persisted by the politeia server.
	Authorize(AuthorizeArgs) error
}

// UserGroup represents a custom user group.
//
// Apps set command permissions by assigning the command a list of user groups
// that are allowed to execute the command. The AuthManager plugin will have
// default user groups that can be used, but an app may also want to create
// user groups that are specific to the app's functionality.
//
// For example, a forum app may want to add a custom forum moderator group. The
// forum moderator group can be given permission to run commands related to
// moderating forum content, but without giving them access to other admin
// commands.
type UserGroup struct {
	Group string

	// AssignedBy contains all of the user groups that are allowed to assign
	// this custom user group.
	AssignedBy []string
}

// CmdPerms represents the permissions for a plugin command.
type CmdPerms struct {
	Cmd CmdDetails

	// Groups contains the user groups that are allowed to execute the command.
	Groups []string
}

// AuthorizeArgs contains the arguments for the Authorize method.
type AuthorizeArgs struct {
	Session Session
	Cmds    []CmdDetails
}

// String returns a string representation of the authorize structure.
func (a *AuthorizeArgs) String() string {
	var cmds strings.Builder
	for _, v := range a.Cmds {
		cmds.WriteString(v.String())
	}
	return fmt.Sprintf("%v %+v", cmds.String(), a.Session.Values())
}
