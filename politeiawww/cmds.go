// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"

	"github.com/decred/politeia/app"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
)

func (p *politeiawww) writeCmd(ctx context.Context, s *app.Session, c v3.Cmd) (*v3.CmdReply, error) {
	pc := convertCmd(c)
	pr, err := p.app.Write(ctx, s, pc)
	if err != nil {
		var ue *app.UserErr
		if errors.As(err, &ue) {
			return convertErrReply(pc, ue), nil
		}
		return nil, err
	}

	return convertReply(pc, *pr), nil
}

func (p *politeiawww) readCmd(ctx context.Context, s *app.Session, c v3.Cmd) (*v3.CmdReply, error) {
	pc := convertCmd(c)
	pr, err := p.app.Read(ctx, s, pc)
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
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Payload: c.Payload,
	}
}

func convertErrReply(c app.Cmd, e *app.UserErr) *v3.CmdReply {
	return &v3.CmdReply{
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Error: &v3.PluginError{
			ErrorCode:    e.Code,
			ErrorContext: e.Context,
		},
	}
}

func convertReply(c app.Cmd, r app.CmdReply) *v3.CmdReply {
	return &v3.CmdReply{
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Payload: r.Payload,
	}
}
