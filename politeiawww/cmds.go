// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"database/sql"
	"fmt"

	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/pkg/errors"
)

// execWrite executes a plugin command that writes data.
//
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin is a
// registered plugin.
func (p *politeiawww) execWrite(ctx context.Context, session *plugin.Session, pluginID string, cmd plugin.Cmd) (*plugin.Reply, error) {
	log.Tracef("execWrite: %v %v %v", pluginID, cmd.Cmd, session.UserID)

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
	var usr *plugin.User
	if session.UserID != "" {
		u, err := p.userDB.TxGet(tx, session.UserID)
		if err != nil {
			return nil, err
		}
		usr = convertUser(u, pluginID)
	}

	// Verify that the user is authorized to execute this
	// plugin command.
	reply, err := p.authorize(session, usr, pluginID, cmd.Cmd)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the pre plugin hooks
	reply, err = p.execPreHooks(tx, plugin.HookPreWrite, cmd, usr)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the plugin command
	plug, ok := p.plugins[pluginID]
	if !ok {
		// Should not happen
		return nil, errors.Errorf("plugin not found: %v", pluginID)
	}
	reply, err = plug.TxWrite(tx, cmd, usr)
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		// The plugin command encountered
		// a user error. Return it.
		return reply, nil
	}

	// Execute the post plugin hooks
	err = p.execPostHooks(tx, plugin.HookPostWrite, cmd, usr)
	if err != nil {
		return nil, err
	}

	// Save any updated user plugin data
	if usr.PluginData.Updated() {
		err = p.userDB.TxUpdate(tx, pluginID,
			usr.PluginData.ClearText(),
			usr.PluginData.Encrypted())
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

// execRead executes a plugin command that writes data.
//
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin is a
// registered plugin.
func (p *politeiawww) execRead(ctx context.Context, session *plugin.Session, pluginID string, cmd plugin.Cmd) (*plugin.Reply, error) {
	log.Tracef("execRead: %v %v %v", pluginID, cmd.Cmd, session.UserID)

	// Get the user. A session user may or may not exist.
	var usr *plugin.User
	if session.UserID != "" {
		u, err := p.userDB.Get(session.UserID)
		if err != nil {
			return nil, err
		}
		usr = convertUser(u, pluginID)
	}

	// Verify that the user is authorized to execute this
	// plugin command.
	reply, err := p.authorize(session, usr, pluginID, cmd.Cmd)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the plugin command
	plug, ok := p.plugins[pluginID]
	if !ok {
		// Should not happen
		return nil, errors.Errorf("plugin not found: %v", pluginID)
	}
	reply, err = plug.Read(cmd, usr)
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

func (p *politeiawww) authorize(s *plugin.Session, u *plugin.User, pluginID, cmd string) (*plugin.Reply, error) {
	err := p.auth.Authorize(s, u, pluginID, cmd)
	if err != nil {
		var ue plugin.UserError
		if errors.As(err, &ue) {
			return &plugin.Reply{
				Error: err,
			}, nil
		}
		return nil, err
	}
	return nil, nil
}

// execPreHooks executes the provided pre hook for all plugins. Pre hooks are
// used to perform validation on the plugin command.
//
// A plugin reply will be returned if one of the plugins throws a user error
// during hook execution. The user error will be embedded in the plugin
// reply. Unexpected errors result in a standard golang error being returned.
func (p *politeiawww) execPreHooks(tx *sql.Tx, h plugin.HookT, cmd plugin.Cmd, usr *plugin.User) (*plugin.Reply, error) {
	err := p.execHooks(tx, h, cmd, usr)
	if err != nil {
		var ue plugin.UserError
		if errors.As(err, &ue) {
			return &plugin.Reply{
				Error: err,
			}, nil
		}
		return nil, err
	}
	return nil, nil
}

// execPostHooks executes the provided post hook for all user plugins.
//
// Post hooks are not able to throw plugin errors like the pre hooks are. Any
// error returned by a plugin from a post hook will be treated as an unexpected
// error.
func (p *politeiawww) execPostHooks(tx *sql.Tx, h plugin.HookT, cmd plugin.Cmd, usr *plugin.User) error {
	return p.execHooks(tx, h, cmd, usr)
}

// execHooks executes a hook for list of plugins. A sql Tx may or may not exist
// depending on the whether the caller is executing an atomic operation.
func (p *politeiawww) execHooks(tx *sql.Tx, h plugin.HookT, cmd plugin.Cmd, usr *plugin.User) error {
	for _, pluginID := range p.pluginIDs {
		// Get the plugin
		p, ok := p.plugins[pluginID]
		if !ok {
			// Should not happen
			return errors.Errorf("plugin not found: %v", pluginID)
		}

		// Execute the hook. Some commands will execute
		// the hook using a database transaction (write
		// commands) and some won't (read-only commands).
		if tx != nil {
			err := p.TxHook(tx, h, cmd, usr)
			if err != nil {
				return err
			}
		} else {
			err := p.Hook(h, cmd, usr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func convertUser(u *user.User, pluginID string) *plugin.User {
	pluginData := u.Plugins[pluginID]
	return &plugin.User{
		ID: u.ID,
		PluginData: plugin.NewPluginData(pluginData.ClearText,
			pluginData.Encrypted),
	}
}
