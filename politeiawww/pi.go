// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piplugin "github.com/decred/politeia/plugins/pi"
)

// piCommentNew calls the pi plugin to add new comment.
func (p *politeiawww) piCommentNew(ncp *piplugin.CommentNew) (*piplugin.CommentNewReply, error) {
	// Prep new comment payload
	payload, err := piplugin.EncodeCommentNew(*ncp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(piplugin.ID, piplugin.CmdCommentNew, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cnr, err := piplugin.DecodeCommentNewReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cnr, nil
}
