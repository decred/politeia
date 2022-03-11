// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	v1 "github.com/decred/politeia/politeiawww/plugins/auth/v1"
)

var (
	_ plugin.AuthManager = (*authPlugin)(nil)
)

// authPlugin implements the plugin package AuthManager interface.
type authPlugin struct{}

// ID returns the plugin ID.
//
// This function satisfies the plugin package AuthManager interface.
func (p *authPlugin) ID() string {
	log.Tracef("ID")

	return v1.PluginID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the plugin package AuthManager interface.
func (p *authPlugin) Version() uint32 {
	log.Tracef("Version")

	return v1.PluginVersion
}

// Authorize checks if the user is authorized to execute a plugin command.
//
// A UserError is returned if the user is not authorized.
//
// This function satisfies the plugin package AuthManager interface.
func (p *authPlugin) Authorize(args plugin.AuthorizeArgs) error {
	log.Tracef("Authorize: %+v", args)

	return nil
}
