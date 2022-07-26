// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/pkg/errors"
)

// Driver provides a standardized set of methods for executing plugin commands
// so that apps do not have to re-implement the same execution logic.
//
// This logic resides in the app layer and not in the politeia backend because,
// as of writing this, I'm not aware of a way to pass a sql transaction from
// the backend to the app if we are using golang plugins (or some variant)
// where the app is run as a separate process that communicates with the main
// politeia process via a RPC or gRPC connection. For this reason, all database
// transaction operations must be performed entirely in the app layer, creating
// the need for this driver.
type Driver struct {
	plugins     map[string]Plugin
	db          *sql.DB
	authManager AuthManager
}

// NewDriver returns a new app Driver.
func NewDriver(plugins []Plugin, db *sql.DB, authMgr AuthManager) *Driver {
	p := make(map[string]Plugin, len(plugins))
	for _, v := range plugins {
		p[v.ID()] = v
	}
	return &Driver{
		plugins:     p,
		db:          db,
		authManager: authMgr,
	}
}

// WriteCmd executes a plugin command that writes data.
//
// Any updates made to the session are persisted by the politeia server.
func (d *Driver) WriteCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	// Setup the database transaction
	tx, cancel, err := d.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Verify that the user is authorized
	// to execute this plugin command.
	err = d.authManager.Authorize(
		AuthorizeArgs{
			Session: s,
			Cmds: []CmdDetails{
				{
					Plugin:  cmd.Plugin,
					Version: cmd.Version,
					Name:    cmd.Name,
				},
			},
		})
	if err != nil {
		return nil, err
	}
	userID := d.authManager.SessionUserID(*s)

	// Execute the pre plugin hooks
	err = d.hook(tx,
		HookArgs{
			Type:   HookPreWrite,
			Cmd:    cmd,
			Reply:  nil,
			UserID: userID,
		})
	if err != nil {
		return nil, err
	}

	// Execute the plugin command
	p := d.plugin(cmd.Plugin)
	reply, err := p.TxWrite(tx,
		WriteArgs{
			Cmd:    cmd,
			UserID: userID,
		})
	if err != nil {
		return nil, err
	}

	// Execute the post plugin hooks
	err = d.hook(tx,
		HookArgs{
			Type:   HookPostWrite,
			Cmd:    cmd,
			Reply:  reply,
			UserID: userID,
		})
	if err != nil {
		return nil, err
	}

	// Commit the database transaction
	err = tx.Commit()
	if err != nil {
		// Attempt to roll back the transaction
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("commit err: %v, rollback err: %v", err, err2))
		}
		return nil, err
	}

	return reply, nil
}

// ReadCmd executes a read-only plugin command.
//
// Any updates made to the session are persisted by the politeia server.
func (d *Driver) ReadCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	// Verify that the user is authorized
	// to execute this plugin command.
	err := d.authManager.Authorize(
		AuthorizeArgs{
			Session: s,
			Cmds: []CmdDetails{
				{
					Plugin:  cmd.Plugin,
					Version: cmd.Version,
					Name:    cmd.Name,
				},
			},
		})
	if err != nil {
		return nil, err
	}
	userID := d.authManager.SessionUserID(*s)

	// Execute the plugin command
	p := d.plugin(cmd.Plugin)
	reply, err := p.Read(
		ReadArgs{
			Cmd:    cmd,
			UserID: userID,
		})
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// hook executes a hook on all plugins.
func (d *Driver) hook(tx *sql.Tx, h HookArgs) error {
	for _, p := range d.sortedPlugins() {
		err := p.TxHook(tx, h)
		if err != nil {
			return err
		}
	}
	return nil
}

// plugin returns a registered plugin.
func (d *Driver) plugin(pluginID string) Plugin {
	return d.plugins[pluginID]
}

// sortedPlugins returns all registered plugins, sorted alphabetically.
func (d *Driver) sortedPlugins() []Plugin {
	ps := make([]Plugin, 0, len(d.plugins))
	for _, v := range d.plugins {
		ps = append(ps, v)
	}
	// Sort plugins alphabetically
	sort.SliceStable(ps, func(i, j int) bool {
		return ps[i].ID() < ps[j].ID()
	})
	return ps
}

// beginTx returns a database transactions and a cancel function for the
// transaction.
//
// The cancel function can be used up until the tx is committed or manually
// rolled back. Invoking the cancel function rolls the tx back and releases all
// resources associated with it. This allows the caller to defer the cancel
// function in order to rollback the tx on unexpected errors. Once the tx is
// successfully committed the deferred invocation of the cancel function does
// nothing.
func (d *Driver) beginTx() (*sql.Tx, func(), error) {
	ctx, cancel := ctxForTx()

	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := d.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	return tx, cancel, nil
}

const (
	// timeoutTx is the timeout for a database transaction.
	timeoutTx = 3 * time.Minute
)

// ctxForTx returns a context and a cancel function for a database transaction.
func ctxForTx() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutTx)
}
