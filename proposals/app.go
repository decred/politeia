// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	"context"
	"database/sql"

	app "github.com/decred/politeia/app/v1"
	"github.com/decred/politeia/plugins/auth"
	"github.com/decred/politeia/politeiawww/user"
)

const (
	// AppID is the app ID for the proposals app.
	AppID = "proposals"
)

var _ app.App = (*proposalsApp)(nil)

// proposalsApp represents the politeia app for the decred proposal system.
//
// proposalsApp satisfies the app/v1 App interface.
type proposalsApp struct {
	plugins []app.Plugin
	authMgr app.AuthManager
	driver  *app.Driver
}

// NewApp returns a new proposals app.
func NewApp() (*proposalsApp, error) {
	var (
		// TODO
		db      *sql.DB
		userDB  user.DB
		plugins = make([]app.Plugin, 0, 64)
	)

	authP := auth.New()

	// Setup the user permissions for the plugin
	// cmds that are part of the proposals app.
	authP.SetCmdPerms(perms())

	return &proposalsApp{
		plugins: plugins,
		authMgr: authP,
		driver:  app.NewDriver(plugins, db, userDB, authP),
	}, nil
}

// Plugins returns all of the plugins that are part of the app.
//
// This function satisfies the app/v1 App interface.
func (a *proposalsApp) Plugins() []app.Plugin {
	return nil
}

// AuthManager returns the app's AuthManager.
//
// This function satisfies the app/v1 App interface.
func (a *proposalsApp) AuthManager() app.AuthManager {
	return a.authMgr
}

// Cmds returns all of the plugin commands that are part of the app.
//
// This function satisfies the app/v1 App interface.
func (a *proposalsApp) Cmds() []app.CmdDetails {
	return nil
}

// PreventBatchedReads returns the list of plugin commands that are not
// allowed to be included in a read batch.
//
// Prior to executing a read batch, the politeia server will verify that the
// read commands are allowed to be executed as part of a read batch. This
// lets the app prevent expensive reads from being batched. By default, all
// read commands are allowed to be batched.
//
// This function satisfies the app/v1 App interface.
func (a *proposalsApp) PreventBatchedReads() []app.CmdDetails {
	return nil
}

// Write executes a plugin write command.
//
// This function satisfies the app/v1 App interface.
func (a *proposalsApp) Write(ctx context.Context, s app.Session, c app.Cmd) (*app.CmdReply, error) {
	return a.driver.WriteCmd(ctx, &s, c)
}
