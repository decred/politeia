// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"

	v1 "github.com/decred/politeia/plugins/auth/v1"
	app "github.com/decred/politeia/politeiawww/app/v1"
)

// plugin.go contains the methods that satisfy the app/v1 Plugin interface.

var (
	_ app.Plugin = (*auth)(nil)
)

// ID returns the plugin ID.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) ID() string {
	return v1.PluginID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) Version() uint32 {
	return v1.PluginVersion
}

// UpdateSettings updates plugin setting values.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) UpdateSettings([]app.Setting) error {
	return nil
}

// Cmds returns all registered plugin commands.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) Cmds() []app.CmdDetails {
	return nil
}

// NewUserCmds returns all of the plugin commands that should result in a new
// user being inserted into the user database.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) NewUserCmds() []app.CmdDetails {
	return nil
}

// Hook executes a plugin hook.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) Hook(a app.HookArgs) error {
	return nil
}

// Read executes a read plugin command.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) Read(a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxHook executes a plugin hook using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) TxHook(tx *sql.Tx, a app.HookArgs) error {
	return nil
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) TxWrite(tx *sql.Tx, a app.WriteArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxRead executes a read plugin command using a database transaction.
//
// This function satisfies the app/v1 Plugin interface.
func (p *auth) TxRead(tx *sql.Tx, a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}
