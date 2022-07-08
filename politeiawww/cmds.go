// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"database/sql"
	"fmt"

	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// newUserCmd executes a plugin command that results in the creation of a new
// user in the user database.
//
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin command is
// the user plugin.
func (p *politeiawww) NewUserCmd(ctx context.Context, s *plugin.Session, c v3.Cmd) (*v3.CmdReply, error) {
	log.Tracef("NewUserCmd: %+v %+v", s, c)

	pc := convertCmd(c)
	pr, err := p.newUserCmd(ctx, s, pc)
	if err != nil {
		var ue *plugin.UserErr
		if errors.As(err, &ue) {
			return convertErrReply(pc, ue), nil
		}
		return nil, err
	}

	return convertReply(pc, *pr), nil
}

// See the NewUserCmd function definition for more details.
func (p *politeiawww) newUserCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.CmdReply, error) {

	// Setup the database transaction
	tx, cancel, err := p.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Setup a new user
	u := &user.User{
		ID:      uuid.New(),
		Plugins: make(map[string]user.PluginData, 64),
	}

	// Verify that the session user, if one exists,
	// is authorized to execute this plugin command.
	err = p.authorize(session, u, cmd)
	if err != nil {
		return nil, err
	}

	// Execute the pre plugin hooks
	err = p.hook(tx, u,
		plugin.HookArgs{
			Type:  plugin.HookPreNewUser,
			Cmd:   cmd,
			Reply: nil,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Execute the new user plugin command
	pu := convertUser(u, cmd.PluginID)
	reply, err := p.userManager.NewUser(tx,
		plugin.WriteArgs{
			Cmd:  cmd,
			User: pu,
		})
	if err != nil {
		return nil, err
	}

	// Update the global user object with any changes
	// that the plugin made to the plugin user data.
	updateUser(u, pu, cmd.PluginID)

	// Execute the post plugin hooks
	err = p.hook(tx, u,
		plugin.HookArgs{
			Type:  plugin.HookPostNewUser,
			Cmd:   cmd,
			Reply: reply,
			User:  nil, // User is set in hook()
		})
	if err != nil {
		return nil, err
	}

	// Insert the user into the database
	err = p.userDB.TxInsert(tx, *u)
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

// authorize uses the AuthManager to check if the user is authorized to
// execute the provided plugin command.
func (p *politeiawww) authorize(s *plugin.Session, u *user.User, c plugin.Cmd) error {
	// Setup the plugin user
	pu := convertUser(u, p.authManager.ID())

	// Check the user authorization
	err := p.authManager.Authorize(
		plugin.AuthorizeArgs{
			Session:  s,
			User:     pu,
			PluginID: c.PluginID,
			Version:  c.Version,
			Cmd:      c.Cmd,
		})
	if err != nil {
		return err
	}

	// Update the global user object with any changes
	// that the plugin made to the plugin user data.
	updateUser(u, pu, c.PluginID)

	return nil
}

// hook executes a hook on on all plugins.
//
// A sql Tx may or may not exist depending on the whether the caller is
// executing an atomic operation.
func (p *politeiawww) hook(tx *sql.Tx, u *user.User, h plugin.HookArgs) error {
	for _, pluginID := range p.pluginIDs {
		// Get the plugin
		p, ok := p.plugins[pluginID]
		if !ok {
			// Should not happen
			return errors.Errorf("plugin not found: %v", pluginID)
		}

		// Add the plugin user to the hook payload
		h.User = convertUser(u, h.Cmd.PluginID)

		// Execute the hook
		err := p.HookTx(tx, h)
		if err != nil {
			return err
		}

		// Update the global user object with any changes
		// that the plugin made to the plugin user data.
		updateUser(u, h.User, h.Cmd.PluginID)
	}

	return nil
}

// updateUser updates the global user object with any changes that were made
// to the plugin user object during command execution.
func updateUser(u *user.User, p *plugin.User, pluginID string) {
	if !p.PluginData.Updated() {
		return
	}

	d := u.Plugins[pluginID]
	d.ClearText = p.PluginData.ClearText()
	d.Encrypted = p.PluginData.Encrypted()

	u.Plugins[pluginID] = d
	u.Updated = true
}

// convertUser converts a global user to a plugin user.
//
// Only the plugin data for the provided plugin ID is included in the plugin
// user object. This prevents plugins from accessing data that they do not own.
func convertUser(u *user.User, pluginID string) *plugin.User {
	d := u.Plugins[pluginID]
	return &plugin.User{
		ID:         u.ID,
		PluginData: plugin.NewPluginData(d.ClearText, d.Encrypted),
	}
}

func convertCmd(c v3.Cmd) plugin.Cmd {
	return plugin.Cmd{
		PluginID: c.PluginID,
		Version:  c.Version,
		Cmd:      c.Cmd,
		Payload:  c.Payload,
	}
}

func convertErrReply(c plugin.Cmd, e *plugin.UserErr) *v3.CmdReply {
	return &v3.CmdReply{
		PluginID: c.PluginID,
		Version:  c.Version,
		Cmd:      c.Cmd,
		Error: &v3.PluginError{
			ErrorCode:    e.ErrCode,
			ErrorContext: e.ErrContext,
		},
	}
}

func convertReply(c plugin.Cmd, r plugin.CmdReply) *v3.CmdReply {
	return &v3.CmdReply{
		PluginID: c.PluginID,
		Version:  c.Version,
		Cmd:      c.Cmd,
		Payload:  r.Payload,
	}
}

/*
// writeCmd executes a plugin command that writes data.
//
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin is a
// registered plugin.
func (p *politeiawww) writeCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.CmdReply, error) {
	log.Tracef("writeCmd: %v %v %v", cmd.PluginID, cmd.Cmd, session.UserID)

	// Setup the database transaction
	tx, cancel, err := p.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Get the user. The session user ID should always
	// exist for writes if the user layer is enabled.
	// If the user layer is disabled, the user ID will
	// be empty.
	var usr *user.User
	if session.UserID != "" {
		usr, err = p.userDB.TxGet(tx, session.UserID)
		if err != nil {
			return nil, err
		}
	}

	// Verify that the user is authorized to
	// execute this plugin command.
	reply, err := p.authorize(session, usr, cmd)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the pre plugin hooks
	reply, err = p.preHooks(tx, usr,
		plugin.HookArgs{
			Type:  plugin.HookPreWrite,
			Cmd:   cmd,
			Reply: nil,
			User:  nil, // User is set in preHooks()
		})
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the plugin command
	plug, ok := p.plugins[cmd.PluginID]
	if !ok {
		// Should not happen
		return nil, errors.Errorf("plugin not found: %v", cmd.PluginID)
	}
	pluginUser := convertUser(usr, cmd.PluginID)
	reply, err = plug.TxWrite(tx,
		plugin.WriteArgs{
			Cmd:  cmd,
			User: pluginUser,
		})
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		// The plugin command encountered
		// a user error. Return it.
		return reply, nil
	}

	// Update the global user object with any changes
	// that the plugin made to the plugin user data.
	updateUser(usr, pluginUser, cmd.PluginID)

	// Execute the post plugin hooks
	err = p.postHooks(tx, usr,
		plugin.HookArgs{
			Type:  plugin.HookPostWrite,
			Cmd:   cmd,
			Reply: reply,
			User:  nil, // User is set in postHooks()
		})
	if err != nil {
		return nil, err
	}

	// Update the user in the database if any
	// updates were made to the user data.
	if usr != nil && usr.Updated {
		err = p.userDB.TxUpdate(tx, *usr)
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

// readCmd executes a read-only plugin command. The read operation is not
// atomic.
//
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin is a
// registered plugin.
func (p *politeiawww) readCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.CmdReply, error) {
	log.Tracef("readCmd: %v %v %v", cmd.PluginID, cmd.Cmd, session.UserID)

	// Get the user. A session user may or may not exist.
	var (
		usr *user.User
		err error
	)
	if session.UserID != "" {
		usr, err = p.userDB.Get(session.UserID)
		if err != nil {
			return nil, err
		}
	}

	// Verify that the user is authorized to
	// execute this plugin command.
	reply, err := p.authorize(session, usr, cmd)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the plugin command
	plug, ok := p.plugins[cmd.PluginID]
	if !ok {
		// Should not happen
		return nil, errors.Errorf("plugin not found: %v", cmd.PluginID)
	}
	reply, err = plug.Read(plugin.ReadArgs{
		Cmd:  cmd,
		User: convertUser(usr, cmd.PluginID),
	})
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		// The plugin command encountered
		// a user error. Return it.
		return reply, nil
	}

	return reply, nil
}
*/
