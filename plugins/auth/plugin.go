// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strconv"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/decred/politeia/util"
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
	perms    map[string]map[string]struct{} // [cmd][permissionLevel]
	settings v1.Settings

	usernameRegexp *regexp.Regexp
}

// New returns a new auth plugin.
func New() (*plugin, error) {
	p := &plugin{
		perms: make(map[string]map[string]struct{}, 256),
		settings: v1.Settings{
			SessionMaxAge:     v1.SessionMaxAge,
			UsernameChars:     v1.UsernameChars,
			UsernameMinLength: v1.UsernameMinLength,
			UsernameMaxLength: v1.UsernameMaxLength,
			PasswordMinLength: v1.PasswordMinLength,
			PasswordMaxLength: v1.PasswordMaxLength,
		},
	}
	err := p.setup()
	if err != nil {
		return nil, err
	}
	return p, nil
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
	// Setup the plugin using the new settings
	err := p.setup()
	if err != nil {
		return err
	}
	return nil
}

// NewUserCmds returns all of the plugin commands that should result in a new
// user being inserted into the user database.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) NewUserCmds() []app.CmdDetails {
	return []app.CmdDetails{
		{
			Plugin:  v1.ID,
			Version: v1.Version,
			Cmd:     v1.CmdNewUser,
		},
	}
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxWrite(tx *sql.Tx, a app.WriteArgs) (*app.CmdReply, error) {
	switch a.Cmd.Name {
	case v1.CmdNewUser:
	}
	return nil, errors.Errorf("invalid cmd")
}

// TxRead executes a read plugin command using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxRead(tx *sql.Tx, a app.ReadArgs) (*app.CmdReply, error) {
	return nil, nil
}

// TxHook executes a plugin hook using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) TxHook(tx *sql.Tx, a app.HookArgs) error {
	return nil
}

// Read executes a non-atomic read plugin command.
//
// This function satisfies the app.Plugin interface.
func (p *plugin) Read(a app.ReadArgs) (*app.CmdReply, error) {
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
		p.settings.SessionMaxAge = i

	case v1.SettingsUsernameChars:
		var chars []string
		err := json.Unmarshal([]byte(s.Value), &chars)
		if err != nil {
			return err
		}
		p.settings.UsernameChars = chars

	case v1.SettingUsernameMinLength:
		u, err := strconv.ParseUint(s.Value, 10, 64)
		if err != nil {
			return err
		}
		p.settings.UsernameMinLength = uint32(u)

	case v1.SettingUsernameMaxLength:
		u, err := strconv.ParseUint(s.Value, 10, 64)
		if err != nil {
			return err
		}
		p.settings.UsernameMaxLength = uint32(u)

	case v1.SettingPasswordMinLength:
		u, err := strconv.ParseUint(s.Value, 10, 64)
		if err != nil {
			return err
		}
		p.settings.PasswordMinLength = uint32(u)

	case v1.SettingPasswordMaxLength:
		u, err := strconv.ParseUint(s.Value, 10, 64)
		if err != nil {
			return err
		}
		p.settings.PasswordMaxLength = uint32(u)

	default:
		return errors.Errorf("setting name not recognized")
	}

	return nil
}

// setup performs plugin setup.
func (p *plugin) setup() error {
	// Setup the regular expressions that are based on plugin
	// settings.
	var err error
	p.usernameRegexp, err = util.Regexp(p.settings.UsernameChars,
		uint64(p.settings.UsernameMinLength),
		uint64(p.settings.UsernameMaxLength))
	if err != nil {
		return err
	}

	return nil
}
