// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import plugin "github.com/decred/politeia/politeiawww/plugin/v1"

// authmanager.go contains the methods that satisfy the plugin package
// AuthManager interface.

var (
	_ plugin.AuthManager = (*auth)(nil)
)

// SetCmdPerms sets the user permission levels for a list of commands.
//
// This function satisfies the plugin/v1 AuthManager interface.
func (p *auth) SetCmdPerms(perms []plugin.CmdPerm) error {
	return nil
}

// Authorize checks if the user is authorized to execute a plugin command.
//
// A UserErr is returned if the user is not authorized.
//
// This function satisfies the plugin/v1 AuthManager interface.
func (p *auth) Authorize(args plugin.AuthorizeArgs) error {
	return nil
}
