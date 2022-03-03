// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"

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
// for the user plugin.
func (p *politeiawww) newUserCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.Reply, error) {
	log.Tracef("newUserCmd: %v %v %v", cmd.PluginID, cmd.Cmd, session.UserID)

	// Setup the database transaction
	tx, cancel, err := p.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Setup a new user
	usr := &user.User{
		ID:      uuid.New(),
		Plugins: make(map[string]user.PluginData, 64),
	}

	// Verify that the session user, if one exists,
	// is authorized to execute this plugin command.
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
			Type:  plugin.HookPreNewUser,
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

	// Execute the new user plugin command
	pluginUser := convertUser(usr, cmd.PluginID)
	reply, err = p.userManager.NewUser(tx,
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
			Type:  plugin.HookPostNewUser,
			Cmd:   cmd,
			Reply: reply,
			User:  nil, // User is set in postHooks()
		})
	if err != nil {
		return nil, err
	}

	// Insert the user into the database
	err = p.userDB.TxInsert(tx, *usr)
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
// Any updates made to the session will be persisted by the caller.
//
// This function assumes the caller has verified that the plugin is a
// registered plugin.
func (p *politeiawww) writeCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.Reply, error) {
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
	reply, err = plug.WriteTx(tx,
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
func (p *politeiawww) readCmd(ctx context.Context, session *plugin.Session, cmd plugin.Cmd) (*plugin.Reply, error) {
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

// preHooks executes the provided pre hook for all plugins. Pre hooks are used
// to perform validation on the plugin command.
//
// A plugin reply will be returned if one of the plugins throws a user error
// during hook execution. The user error will be embedded in the plugin
// reply. Unexpected errors result in a standard golang error being returned.
func (p *politeiawww) preHooks(tx *sql.Tx, usr *user.User, h plugin.HookArgs) (*plugin.Reply, error) {
	err := p.hook(tx, h, usr)
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

// postHooks executes the provided post hook for all user plugins.
//
// Post hooks are not able to throw plugin errors like the pre hooks are. Any
// error returned by a plugin from a post hook will be treated as an unexpected
// error.
func (p *politeiawww) postHooks(tx *sql.Tx, usr *user.User, h plugin.HookArgs) error {
	return p.hook(tx, h, usr)
}

// hook executes a hook on on all plugins. A sql Tx may or may not exist
// depending on the whether the caller is executing an atomic operation.
func (p *politeiawww) hook(tx *sql.Tx, h plugin.HookArgs, usr *user.User) error {
	for _, pluginID := range p.pluginIDs {
		// Get the plugin
		p, ok := p.plugins[pluginID]
		if !ok {
			// Should not happen
			return errors.Errorf("plugin not found: %v", pluginID)
		}

		// Add the plugin user to the hook payload
		h.User = convertUser(usr, h.Cmd.PluginID)

		// Execute the hook. Some commands will execute
		// the hook using a database transaction (write
		// commands) and some won't (read-only commands).
		if tx != nil {
			err := p.HookTx(tx, h)
			if err != nil {
				return err
			}
		} else {
			err := p.Hook(h)
			if err != nil {
				return err
			}
		}

		// Update the global user object with any changes
		// that the plugin made to the plugin user data.
		updateUser(usr, h.User, h.Cmd.PluginID)
	}

	return nil
}

func (p *politeiawww) authorize(s *plugin.Session, usr *user.User, cmd plugin.Cmd) (*plugin.Reply, error) {
	// Setup the plugin user
	pluginUser := convertUser(usr, p.authManager.ID())

	// Check user authorization
	err := p.authManager.Authorize(
		plugin.AuthorizeArgs{
			Session:  s,
			User:     pluginUser,
			PluginID: cmd.PluginID,
			Version:  cmd.Version,
			Cmd:      cmd.Cmd,
		})
	if err != nil {
		var ue plugin.UserError
		if errors.As(err, &ue) {
			return &plugin.Reply{
				Error: err,
			}, nil
		}
		return nil, err
	}

	// Update the global user object with any changes
	// that the plugin made to the plugin user data.
	updateUser(usr, pluginUser, cmd.PluginID)

	return nil, nil
}

// updateUser updates the global user object with any changes that were made
// to the plugin user object during plugin command execution.
func updateUser(u *user.User, p *plugin.User, pluginID string) {
	if !p.PluginData.Updated() {
		return
	}

	pluginData := u.Plugins[pluginID]
	pluginData.ClearText = p.PluginData.ClearText()
	pluginData.Encrypted = p.PluginData.Encrypted()

	u.Plugins[pluginID] = pluginData
	u.Updated = true
}

// convertUser converts a global user to a plugin user. Only the plugin data
// for the provided plugin ID is included in the plugin user object. This
// prevents plugins from accessing data that they do not own.
func convertUser(u *user.User, pluginID string) *plugin.User {
	pluginData := u.Plugins[pluginID]
	return &plugin.User{
		ID: u.ID,
		PluginData: plugin.NewPluginData(pluginData.ClearText,
			pluginData.Encrypted),
	}
}

var (
	// regexpPluginSettingMulti matches against the plugin setting
	// value when it contains multiple values.
	//
	// pluginID,key,["value1","value2"] matches ["value1","value2"]
	regexpPluginSettingMulti = regexp.MustCompile(`(\[.*\]$)`)
)
