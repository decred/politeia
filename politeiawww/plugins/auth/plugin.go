// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"

	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	v1 "github.com/decred/politeia/politeiawww/plugins/auth/v1"
)

// plugin.go contains the methods that satisfy the plugin package Plugin
// interface.

var (
	_ plugin.Plugin = (*auth)(nil)
)

// ID returns the plugin ID.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) ID() string {
	return v1.PluginID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) Version() uint32 {
	return v1.PluginVersion
}

// Hook executes a plugin hook.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) Hook(a plugin.HookArgs) error {
	return nil
}

// Read executes a read plugin command.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) Read(a plugin.ReadArgs) (*plugin.CmdReply, error) {
	return nil, nil
}

// TxHook executes a plugin hook using a database transaction.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) TxHook(tx *sql.Tx, a plugin.HookArgs) error {
	return nil
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) TxWrite(tx *sql.Tx, a plugin.WriteArgs) (*plugin.CmdReply, error) {
	return nil, nil
}

// TxRead executes a read plugin command using a database transaction.
//
// This function satisfies the plugin/v1 Plugin interface.
func (p *auth) TxRead(tx *sql.Tx, a plugin.ReadArgs) (*plugin.CmdReply, error) {
	return nil, nil
}
