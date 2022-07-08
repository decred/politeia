// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"

	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	app "github.com/decred/politeia/politeiawww/app/v1"
)

func (p *politeiawww) writeCmd(ctx context.Context, s *app.Session, c v3.Cmd) (*v3.CmdReply, error) {
	log.Tracef("writeCmd: %v %v %v %+v", c.PluginID, c.Version, c.Name, s)

	pc := convertCmd(c)
	pr, err := p.app.Write(ctx, *s, pc)
	if err != nil {
		var ue *app.UserErr
		if errors.As(err, &ue) {
			return convertErrReply(pc, ue), nil
		}
		return nil, err
	}

	return convertReply(pc, *pr), nil
}

func convertCmd(c v3.Cmd) app.Cmd {
	return app.Cmd{
		PluginID: c.PluginID,
		Version:  c.Version,
		Name:     c.Name,
		Payload:  c.Payload,
	}
}

func convertErrReply(c app.Cmd, e *app.UserErr) *v3.CmdReply {
	return &v3.CmdReply{
		PluginID: c.PluginID,
		Version:  c.Version,
		Name:     c.Name,
		Error: &v3.PluginError{
			ErrorCode:    e.ErrCode,
			ErrorContext: e.ErrContext,
		},
	}
}

func convertReply(c app.Cmd, r app.CmdReply) *v3.CmdReply {
	return &v3.CmdReply{
		PluginID: c.PluginID,
		Version:  c.Version,
		Name:     c.Name,
		Payload:  r.Payload,
	}
}

/*
// newUserCmd executes a plugin command that results in the creation of a new
// user in the user database.
//
// Any updates made to the session during command execution are persisted by
// the politeia backend.
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
