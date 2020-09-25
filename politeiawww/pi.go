// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piplugin "github.com/decred/politeia/plugins/pi"
)

// voteInventoryPi calls the pi plugin to retrieve the token inventory.
func (p *politeiawww) voteInventoryPi(vi piplugin.VoteInventory) (*piplugin.VoteInventoryReply, error) {
	// Prep plugin payload
	payload, err := piplugin.EncodeVoteInventory(vi)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(piplugin.ID, piplugin.CmdVoteInventory, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	vir, err := piplugin.DecodeVoteInventoryReply(([]byte(r)))
	if err != nil {
		return nil, err
	}

	return vir, nil
}

// commentCensorPi calls the pi plugin to censor a given comment.
func (p *politeiawww) commentCensorPi(cc piplugin.CommentCensor) (*piplugin.CommentCensorReply, error) {
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

// commentVotePi calls the pi plugin to vote on a comment.
func (p *politeiawww) commentVotePi(cvp piplugin.CommentVote) (*piplugin.CommentVoteReply, error) {
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

// commentNewPi calls the pi plugin to add new comment.
func (p *politeiawww) commentNewPi(cnp piplugin.CommentNew) (*piplugin.CommentNewReply, error) {
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
