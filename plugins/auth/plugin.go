// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"
	"fmt"

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
	db       *sql.DB
	settings settings
	perms    map[string]map[string]struct{} // [cmd][permissionLevel]
}

// New returns a new auth plugin.
func New(a app.PluginArgs) (*plugin, error) {
	s, err := newSettings(a.Settings)
	if err != nil {
		return nil, err
	}
	return &plugin{
		db:       a.DB,
		settings: *s,
		perms:    make(map[string]map[string]struct{}, 256),
	}, nil
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
	var (
		reply *app.CmdReply
		err   error
	)
	switch a.Cmd.Name {
	case v1.CmdNewUser:
		reply, err = p.cmdNewUser(tx, a.Cmd)
	default:
		return nil, errors.Errorf("invalid cmd")
	}
	if err != nil {
		var ue *userErr
		if errors.As(err, &ue) {
			// Convert the local user error
			// type to an app user error.
			return nil, app.UserErr{
				Code:    uint32(ue.Code),
				Context: ue.Context,
			}
		}
		return nil, err
	}

	return reply, nil
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

// userErr represents an error that occurred during the execution of a plugin
// command and that was caused by the user.
//
// This local userErr is used instead of the app UserErr to allow for more
// readable code. Using the app UserErr leads to uint32(v1.ErrCode) conversions
// all over the place, so instead, the plugin commands will return this local
// error type and the exported methods perform the conversion to the app
// UserErr before returning it.
type userErr struct {
	Code    v1.ErrCode
	Context string
}

// Error satisfies the error interface.
func (e userErr) Error() string {
	if e.Context == "" {
		return fmt.Sprintf("auth plugin user err: %v", e.Code)
	}
	return fmt.Sprintf("auth plugin user err: %v - %v", e.Code, e.Context)
}
