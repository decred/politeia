// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"context"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/server/api/v1"
	"github.com/pkg/errors"
)

func (s *Server) writeCmd(ctx context.Context, sn *app.Session, c v1.Cmd) (*v1.CmdReply, error) {
	pc := convertCmd(c)
	pr, err := s.app.Write(ctx, sn, pc)
	if err != nil {
		var ue app.UserErr
		if errors.As(err, &ue) {
			return convertErrReply(pc, ue), nil
		}
		return nil, err
	}

	return convertReply(pc, *pr), nil
}

func (s *Server) readCmd(ctx context.Context, sn app.Session, c v1.Cmd) (*v1.CmdReply, error) {
	pc := convertCmd(c)
	pr, err := s.app.Read(ctx, sn, pc)
	if err != nil {
		var ue app.UserErr
		if errors.As(err, &ue) {
			return convertErrReply(pc, ue), nil
		}
		return nil, err
	}

	return convertReply(pc, *pr), nil
}

func convertCmd(c v1.Cmd) app.Cmd {
	return app.Cmd{
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Payload: c.Payload,
	}
}

func convertErrReply(c app.Cmd, e app.UserErr) *v1.CmdReply {
	return &v1.CmdReply{
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Error: &v1.PluginError{
			Code:    e.Code,
			Context: e.Context,
		},
	}
}

func convertReply(c app.Cmd, r app.CmdReply) *v1.CmdReply {
	return &v1.CmdReply{
		Plugin:  c.Plugin,
		Version: c.Version,
		Name:    c.Name,
		Payload: r.Payload,
	}
}
