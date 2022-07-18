// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"
	"strconv"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/pkg/errors"
)

var (
	_ app.Plugin = (*plugin)(nil)
)

// plugin represents the auth plugin.
//
// plugin satisfies the app.Plugin interface.
// plugin satisfies the app.AuthManager interface.
type plugin struct {
	perms map[string]map[string]struct{} // [cmd][permissionLevel]

	// Plugin settings
	sessionMaxAge int64
}

// New returns a new auth plugin.
func New() *plugin {
	return &plugin{
		perms:         make(map[string]map[string]struct{}, 256),
		sessionMaxAge: v1.SessionMaxAge,
	}
}

// ID returns the plugin ID.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) ID() string {
	return v1.ID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) Version() uint32 {
	return v1.Version
}

// UpdateSettings updates the plugin settings.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) UpdateSettings(settings []app.Setting) error {
	for _, s := range settings {
		err := p.parseSetting(s)
		if err != nil {
			return errors.Errorf("failed to parse setting %+v: %v", s, err)
		}
		log.Infof("Plugin setting %v updated to %v", s.Name, s.Value)
	}
	return nil
}

// NewUserCmds returns all of the plugin commands that should result in a new
// user being inserted into the user database.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) NewUserCmds() []app.CmdDetails {
	return []app.CmdDetails{}
}

// Hook executes a plugin hook.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) Hook(a app.HookArgs) error {
	return nil
}

// Read executes a read plugin command.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) Read(a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxHook executes a plugin hook using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxHook(tx *sql.Tx, a app.HookArgs) error {
	return nil
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxWrite(tx *sql.Tx, a app.WriteArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxRead executes a read plugin command using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxRead(tx *sql.Tx, a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}

// parseSetting parses the plugin setting and updates the plugin context with
// the setting.
func (p *plugin) parseSetting(s app.Setting) error {
	switch s.Name {
	case v1.SettingSessionMaxAge:
		i, err := strconv.ParseInt(s.Value, 10, 64)
		if err != nil {
			return err
		}
		p.sessionMaxAge = i

	default:
		return errors.Errorf("setting name not recognized")
	}

	return nil
}
