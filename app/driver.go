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

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
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
	userDB      user.DB
	authManager AuthManager

	// newUserCmds contains all of the commands that result in a new user being
	// inserted into the database. New user writes are executed differently than
	// standard writes, so the driver needs prior knowledge of what commands are
	// new user commands.
	newUserCmds map[string]struct{}
}

// NewDriver returns a new app Driver.
func NewDriver(plugins []Plugin, db *sql.DB, userDB user.DB, authMgr AuthManager) *Driver {
	var (
		pluginsM    = make(map[string]Plugin, len(plugins))
		newUserCmds = make(map[string]struct{}, 64)
	)
	for _, p := range plugins {
		pluginsM[p.ID()] = p
		for _, c := range p.NewUserCmds() {
			newUserCmds[c.String()] = struct{}{}
		}
	}
	return &Driver{
		plugins:     pluginsM,
		db:          db,
		userDB:      userDB,
		authManager: authMgr,
		newUserCmds: newUserCmds,
	}
}

// WriteCmd executes a plugin command that writes data.
//
// Any updates made to the session are persisted by the politeia server.
func (d *Driver) WriteCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	if d.isNewUserCmd(cmd) {
		return d.newUserCmd(ctx, s, cmd)
	}
	return d.writeCmd(ctx, s, cmd)
}

// ReadCmd executes a read-only plugin command.
//
// Any updates made to the session are persisted by the politeia server.
func (d *Driver) ReadCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	// Get the user if one exist. It's possible
	// that this is a public command and a user
	// may not exist.
	var (
		userID = d.authManager.SessionUserID(*s)
		u      *user.User
		err    error
	)
	if userID != "" {
		u, err = d.userDB.Get(userID)
		if err != nil {
			return nil, err
		}
	}

	// Verify that the user is authorized
	// to execute this plugin command.
	err = d.authorize(s, u, cmd)
	if err != nil {
		return nil, err
	}

	// Execute the plugin command
	var (
		p  = d.plugin(cmd.PluginID)
		au = convertUser(u, cmd.PluginID)
	)
	reply, err := p.Read(
		ReadArgs{
			Cmd:  cmd,
			User: au,
		})
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// newUserCmd executes a plugin command that results in the creation of a new
// user in the user database.
//
// Plugins do not have direct access to the user database, so they are not able
// to insert new user records. This function inserts a new user into the
// database then passes the newly created user to the plugin command. The
// database transaction that was used to create the user record will only be
// committed if the plugin command executes without any errors.
//
// Any updates made to the session during command execution are persisted by
// the politeia backend.
func (d *Driver) newUserCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	// Setup the database transaction
	tx, cancel, err := d.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Insert a new user into the database. The
	// transaction will not be committed until
	// the plugin command executes successfully.
	u := user.NewUser(uuid.New())
	err = d.userDB.TxInsert(tx, *u)
	if err != nil {
		return nil, err
	}

	// Verify that the user is authorized
	// to execute this plugin command.
	err = d.authorize(s, u, cmd)
	if err != nil {
		return nil, err
	}

	// Execute the pre plugin hooks
	err = d.hook(tx, u,
		HookArgs{
			Type:  HookPreNewUser,
			Cmd:   cmd,
			Reply: nil,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Execute the new user plugin command
	var (
		p  = d.plugin(cmd.PluginID)
		au = convertUser(u, cmd.PluginID)
	)
	reply, err := p.TxWrite(tx,
		WriteArgs{
			Cmd:  cmd,
			User: au,
		})
	if err != nil {
		return nil, err
	}

	// Update the global user with any changes
	// that were made to the user data by the
	// plugin.
	if au.Updated() {
		u.SetData(cmd.PluginID, au.Data())
	}

	// Execute the post plugin hooks
	err = d.hook(tx, u,
		HookArgs{
			Type:  HookPostNewUser,
			Cmd:   cmd,
			Reply: reply,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Save any updates that were made to
	// the user data by the plugins.
	err = d.userDB.TxUpdate(tx, *u)
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

// writeCmd executes a plugin command that writes data.
//
// Any updates made to the session during command execution are persisted by
// the politeia backend.
func (d *Driver) writeCmd(ctx context.Context, s *Session, cmd Cmd) (*CmdReply, error) {
	// Setup the database transaction
	tx, cancel, err := d.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Get the user. Even though this is a write
	// command, the session may not correspond
	// to a logged in user, so the user ID could
	// be empty. It is the responsibility of the
	// auth manager to handle this.
	var (
		userID = d.authManager.SessionUserID(*s)
		u      *user.User
	)
	if userID != "" {
		u, err = d.userDB.TxGet(tx, userID)
		if err != nil {
			return nil, err
		}
	}

	// Verify that the user is authorized
	// to execute this plugin command.
	err = d.authorize(s, u, cmd)
	if err != nil {
		return nil, err
	}

	// Execute the pre plugin hooks
	err = d.hook(tx, u,
		HookArgs{
			Type:  HookPreWrite,
			Cmd:   cmd,
			Reply: nil,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Execute the plugin command
	var (
		p  = d.plugin(cmd.PluginID)
		au = convertUser(u, cmd.PluginID)
	)
	reply, err := p.TxWrite(tx,
		WriteArgs{
			Cmd:  cmd,
			User: au,
		})
	if err != nil {
		return nil, err
	}

	// Update the global user with any changes
	// that were made to the user data by the
	// plugin.
	if au.Updated() {
		u.SetData(cmd.PluginID, au.Data())
	}

	// Execute the post plugin hooks
	err = d.hook(tx, u,
		HookArgs{
			Type:  HookPostWrite,
			Cmd:   cmd,
			Reply: reply,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Save any updates that were made to
	// the user data by the plugins.
	if u != nil && u.Updated() {
		err = d.userDB.TxUpdate(tx, *u)
		if err != nil {
			return nil, err
		}
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

// authorize uses the AuthManager to check if the user is authorized to
// execute the provided plugin command.
func (d *Driver) authorize(s *Session, u *user.User, c Cmd) error {
	au := convertUser(u, d.authManager.ID())
	return d.authManager.Authorize(
		AuthorizeArgs{
			Session: s,
			User:    *au,
			Cmd: CmdDetails{
				PluginID: c.PluginID,
				Version:  c.Version,
				Name:     c.Name,
			},
		})
}

// hook executes a hook on on all plugins.
func (d *Driver) hook(tx *sql.Tx, u *user.User, h HookArgs) error {
	for _, p := range d.sortedPlugins() {
		// Add the app user to the hook payload
		au := convertUser(u, p.ID())
		h.User = au

		// Execute the hook
		err := p.TxHook(tx, h)
		if err != nil {
			return err
		}

		// Update the global user with any changes
		// that the plugin made to the user data.
		if au.Updated() {
			u.SetData(p.ID(), au.Data())
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

// isNewUserCmd returns whether a command is a new user command.
func (d *Driver) isNewUserCmd(c Cmd) bool {
	_, ok := d.newUserCmds[c.String()]
	return ok
}

// convertUser converts a global user to an app user.
//
// Only the plugin data for the provided plugin ID is included in the plugin
// user object. This prevents plugins from accessing data that they do not own.
func convertUser(u *user.User, pluginID string) *User {
	b := u.Data(pluginID)
	return NewUser(u.ID, b)
}

// updateUser updates the global user with any changes that were made to the
// app user during command execution.
func _updateUser(globalU *user.User, appU *User, pluginID string) {
	if !appU.Updated() {
		return
	}
	globalU.SetData(pluginID, appU.Data())
}

const (
	// timeoutOp is the timeout for a single database operation.
	timeoutOp = 1 * time.Minute

	// timeoutTx is the timeout for a database transaction.
	timeoutTx = 3 * time.Minute
)

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

// ctxForOp returns a context and cancel function for a single database
// operation.
func ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutOp)
}

// ctxForTx returns a context and a cancel function for a database transaction.
func ctxForTx() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutTx)
}
