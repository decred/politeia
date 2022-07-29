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

// plugin.go contains the methods that satisfy the app.Plugin interface.

var (
	_ app.Plugin = (*authp)(nil)
)

// ID returns the plugin ID.
//
// This function satisfies the app.Plugin interface.
func (p *authp) ID() string {
	log.Tracef("ID")

	return v1.PluginID
}

// Version returns the lowest supported plugin API version.
//
// This function satisfies the app.Plugin interface.
func (p *authp) Version() uint32 {
	log.Tracef("Version")

	return v1.Version
}

// TxWrite executes a write plugin command using a database transaction.
//
// This function satisfies the app.Plugin interface.
func (p *authp) TxWrite(tx *sql.Tx, a app.WriteArgs) (*app.CmdReply, error) {
	log.Tracef("TxWrite %v", &a)

	var (
		reply *app.CmdReply
		err   error
	)
	switch a.Cmd.Name {
	case v1.CmdNewUser:
		reply, err = p.cmdNewUser(tx, a.Cmd)
	case v1.CmdLogin:
		reply, err = p.cmdLogin(tx, a.Cmd, a.Session)
	case v1.CmdLogout:
		reply, err = p.cmdLogout(tx, a.Cmd, a.Session)
	default:
		return nil, errors.Errorf("invalid cmd")
	}
	if err != nil {
		var ue userErr
		if errors.As(err, &ue) {
			// Convert the local user error to an app
			// user error.
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
func (p *authp) TxRead(tx *sql.Tx, a app.ReadArgs) (*app.CmdReply, error) {
	log.Tracef("TxRead %v", &a)

	return p.read(tx, a)
}

// Read executes a non-atomic, read-only plugin command.
//
// This function satisfies the app.Plugin interface.
func (p *authp) Read(a app.ReadArgs) (*app.CmdReply, error) {
	log.Tracef("Read %v", &a)

	return p.read(p.db, a)
}

// read contains all of the auth plugin read commands. The caller can decide
// whether the command should be executed as part of a transaction or as an
// individual command.
func (p *authp) read(q querier, a app.ReadArgs) (*app.CmdReply, error) {
	var (
		reply *app.CmdReply
		err   error
	)
	switch a.Cmd.Name {
	case v1.CmdMe:
		reply, err = p.cmdMe(q, a.Cmd, a.UserID)
	default:
		return nil, errors.Errorf("invalid cmd")
	}
	if err != nil {
		var ue userErr
		if errors.As(err, &ue) {
			// Convert the local user error to an app
			// user error.
			return nil, app.UserErr{
				Code:    uint32(ue.Code),
				Context: ue.Context,
			}
		}
		return nil, err
	}

	return reply, nil
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
