// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"

	app "github.com/decred/politeia/app/v1"
	v1 "github.com/decred/politeia/plugins/auth/v1"
)

// plugin.go contains the methods that satisfy the app/v1 Plugin interface.

var (
	_ app.Plugin = (*plugin)(nil)
)

// plugin represents the auth plugin.
//
// plugin satisfies the app/v1 Plugin interface.
// plugin satisfies the app/v1 AuthManager interface.
type plugin struct {
	perms map[string]map[string]struct{} // [cmd][permissionLevel]
}

// New returns a new auth plugin.
func New() *plugin {
	return &plugin{
		perms: make(map[string]map[string]struct{}, 256),
	}
}

// ID returns the plugin ID.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) ID() string {
	return v1.PluginID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) Version() uint32 {
	return v1.PluginVersion
}

// UpdateSettings updates the plugin settings.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) UpdateSettings([]app.Setting) error {
	return nil
}

// NewUserCmds returns all of the plugin commands that should result in a new
// user being inserted into the user database.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) NewUserCmds() []app.CmdDetails {
	return nil
}

// Hook executes a plugin hook.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) Hook(a app.HookArgs) error {
	return nil
}

// Read executes a read plugin command.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) Read(a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxHook executes a plugin hook using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) TxHook(tx *sql.Tx, a app.HookArgs) error {
	return nil
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) TxWrite(tx *sql.Tx, a app.WriteArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxRead executes a read plugin command using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *plugin) TxRead(tx *sql.Tx, a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}
