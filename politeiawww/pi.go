// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piplugin "github.com/decred/politeia/plugins/pi"
)

// commentCensor calls the pi plugin to censor a given comment.
func (p *politeiawww) commentCensor(cc piplugin.CommentCensor) (*piplugin.CommentCensorReply, error) {
	// Prep plugin payload
	payload, err := piplugin.EncodeCommentCensor(cc)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(piplugin.ID, piplugin.CmdCommentCensor, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	ccr, err := piplugin.DecodeCommentCensorReply(([]byte(r)))
	if err != nil {
		return nil, err
	}

	return ccr, nil
}

// piCommentVote calls the pi plugin to vote on a comment.
func (p *politeiawww) piCommentVote(cvp piplugin.CommentVote) (*piplugin.CommentVoteReply, error) {
	// Prep comment vote payload
	payload, err := piplugin.EncodeCommentVote(cvp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(piplugin.ID, piplugin.CmdCommentVote, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cvr, err := piplugin.DecodeCommentVoteReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cvr, nil
}

// piCommentNew calls the pi plugin to add new comment.
func (p *politeiawww) piCommentNew(cnp piplugin.CommentNew) (*piplugin.CommentNewReply, error) {
	// Prep new comment payload
	payload, err := piplugin.EncodeCommentNew(cnp)
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
