// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	"context"
	"database/sql"

	"github.com/decred/politeia/app"
	"github.com/decred/politeia/plugins/auth"
	"github.com/decred/politeia/politeiawww/user"
)

const (
	// AppID is the app ID for the proposals app.
	AppID = "proposals"
)

var _ app.App = (*appCtx)(nil)

// appCtx is the politeia app for the decred proposal system.
//
// appCtx satisfies the app/v1 App interface.
type appCtx struct {
	plugins []app.Plugin
	driver  *app.Driver
}

// NewApp returns a new proposals app.
func NewApp(a app.InitArgs) (*appCtx, error) {
	var (
		// TODO setup the database connection
		// each app should have it's own database
		db      *sql.DB
		userDB  user.DB
		plugins = make([]app.Plugin, 0, 64)
	)
	/*
		log.Infof("MySQL host: %v:[password]@tcp(%v)/%v", user, host, dbname)

		h := fmt.Sprintf("%v:%v@tcp(%v)/%v", user, password, host, dbname)
		db, err := sql.Open("mysql", h)
		if err != nil {
			return nil, err
		}

		// Verify the database connection
		err = db.Ping()
		if err != nil {
			return nil, err
		}

		// Setup database options
		db.SetConnMaxLifetime(connMaxLifetime)
		db.SetMaxOpenConns(maxOpenConns)
		db.SetMaxIdleConns(maxIdleConns)
	*/

	authP := auth.New()

	// Setup the user permissions for the plugin
	// cmds that are part of the proposals app.
	authP.SetCmdPerms(perms())

	// Update the default plugin settings with
	// the settings that were provided in the
	// config at runtime.
	for _, p := range plugins {
		s, ok := a.Settings[p.ID()]
		if !ok {
			continue
		}
		p.UpdateSettings(s)
	}

	return &appCtx{
		plugins: plugins,
		driver:  app.NewDriver(plugins, db, userDB, authP),
	}, nil
}

// Cmds returns all of the plugin commands that are part of the app.
//
// This function satisfies the app/v1 App interface.
func (a *appCtx) Cmds() []app.CmdDetails {
	// We've already created a list of all the cmds
	// that are part of the app when we created the
	// cmd permissions list. Re-use this same list.
	cmds := make([]app.CmdDetails, 0, 256)
	for _, perm := range perms() {
		cmds = append(cmds, perm.Cmd)
	}
	return cmds
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
func (a *appCtx) PreventBatchedReads() []app.CmdDetails {
	return nil
}

// Write executes a plugin write command.
//
// This function satisfies the app/v1 App interface.
func (a *appCtx) Write(ctx context.Context, s app.Session, c app.Cmd) (*app.CmdReply, error) {
	return a.driver.WriteCmd(ctx, &s, c)
}
