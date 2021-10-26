// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"database/sql"
	"fmt"

	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/pkg/errors"
)

// execWrite executes a plugin command that writes data.
func (p *politeiawww) execWrite(ctx context.Context, cmd plugin.Cmd, s *plugin.Session) (*plugin.Reply, error) {
	// Start the database transaction
	tx, cancel, err := p.beginTx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Execute the pre plugin hooks
	reply, err := p.execPreHooks(tx, plugin.HookPreWrite, cmd, s)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		return reply, nil
	}

	// Execute the plugin command
	reply, err = p.execCmd(cmd, s)
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		// The plugin command encountered an
		// expected error. Nothing else to do.
		return reply, nil
	}

	// Execute the post plugin hooks
	err = p.execPostHooks(tx, plugin.HookPostWrite, cmd, s)
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

func (p *politeiawww) execCmd(cmd plugin.Cmd, s *plugin.Session) (*plugin.Reply, error) {
	// Get the plugin

	// Execute the plugin command

	return nil, nil
}

// execPreHooks executes the provided pre hook for all plugins. Pre hooks are
// used to perform validation on the plugin command.
//
// A plugin reply will be returned if one of the plugins throws a user error
// during hook execution. The user error will be embedded in the plugin
// reply. Unexpected errors result in a standard golang error being returned.
func (p *politeiawww) execPreHooks(tx *sql.Tx, h plugin.HookT, cmd plugin.Cmd, s *plugin.Session) (*plugin.Reply, error) {
	// Execute hooks for auth plugins
	err := p.execHooks(p.authPlugins, tx, h, cmd, s)
	if err != nil {
		var ue plugin.UserError
		if errors.As(err, &ue) {
			return &plugin.Reply{
				Error: err,
			}, nil
		}
		return nil, err
	}

	// Execute hooks for standard plugins
	err = p.execHooks(p.standardPlugins, tx, h, cmd, s)
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
func (p *politeiawww) execPostHooks(tx *sql.Tx, h plugin.HookT, cmd plugin.Cmd, s *plugin.Session) error {
	// Execute hooks for auth plugins
	err := p.execHooks(p.authPlugins, tx, h, cmd, s)
	if err != nil {
		return err
	}

	// Execute hooks for standard plugins
	err = p.execHooks(p.standardPlugins, tx, h, cmd, s)
	if err != nil {
		return err
	}

	return nil
}

// execHooks executes a hook for list of plugins. A sql Tx may or may not exist
// depending on the whether the caller is executing an atomic operation.
func (p *politeiawww) execHooks(pluginIDs []string, tx *sql.Tx, h plugin.HookT,
	cmd plugin.Cmd, s *plugin.Session) error {
	for _, pluginID := range pluginIDs {
		p, ok := p.plugins[pluginID]
		if !ok {
			// Should not happen
			return errors.Errorf("plugin not found: %v",
				pluginID)
		}
		if tx != nil {
			err := p.TxHook(tx, h, cmd, s)
			if err != nil {
				return err
			}
		} else {
			err := p.Hook(h, cmd, s)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
