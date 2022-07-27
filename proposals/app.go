// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/decred/politeia/app"
	"github.com/decred/politeia/plugins/auth"
	authv1 "github.com/decred/politeia/plugins/auth/v1"
)

const (
	// AppID is the app ID for the proposals app.
	AppID = "proposals"
)

var _ app.App = (*appCtx)(nil)

// appCtx is the politeia app for the decred proposal system.
//
// appCtx satisfies the app.App interface.
type appCtx struct {
	plugins []app.Plugin
	driver  *app.Driver
}

// NewApp returns a new proposals app.
func NewApp(a app.AppArgs) (*appCtx, error) {
	// TODO hardcoding bad
	var (
		connMaxLifetime = 0 * time.Minute // 0 is unlimited
		maxOpenConns    = 0               // 0 is unlimited
		maxIdleConns    = 10

		user     = "politeiawww"
		password = a.DBPass
		host     = a.DBHost
		dbname   = "proposals_testnet3"
	)

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", user, password, host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	settings := a.Settings[authv1.PluginID]
	authP, err := auth.New(app.PluginArgs{
		Settings: settings,
		DB:       db,
	})
	if err != nil {
		return nil, err
	}

	// Setup the user permissions for the plugin
	// cmds that are part of the proposals app.
	authP.SetCmdPerms(perms())

	var (
		// TODO
		plugins = []app.Plugin{authP}
	)

	return &appCtx{
		plugins: plugins,
		driver:  app.NewDriver(plugins, db, authP),
	}, nil
}

// Cmds returns all of the plugin commands that are part of the app.
//
// This function satisfies the app.App interface.
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
// This function satisfies the app.App interface.
func (a *appCtx) PreventBatchedReads() []app.CmdDetails {
	return nil
}

// Write executes a plugin write command.
//
// Any updates make to the session will be persisted by the politeia server.
//
// This function satisfies the app.App interface.
func (a *appCtx) Write(ctx context.Context, s *app.Session, c app.Cmd) (*app.CmdReply, error) {
	log.Tracef("Write %v", &c)

	return a.driver.WriteCmd(ctx, s, c)
}

// Read executes a read-only plugin command.
//
// Any updates make to the session will be persisted by the politeia server.
//
// This function satisfies the app.App interface.
func (a *appCtx) Read(ctx context.Context, s *app.Session, c app.Cmd) (*app.CmdReply, error) {
	log.Tracef("Read %v", &c)

	return a.driver.ReadCmd(ctx, s, c)
}
