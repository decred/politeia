// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"

	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
)

// piProposals returns the pi plugin data for the provided proposals.
func (p *politeiawww) piProposals(ctx context.Context, ps piplugin.Proposals) (*piplugin.ProposalsReply, error) {
	b, err := piplugin.EncodeProposals(ps)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID, piplugin.CmdProposals, string(b))
	if err != nil {
		return nil, err
	}
	pr, err := piplugin.DecodeProposalsReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return pr, nil
}

// piCommentNew uses the pi plugin to submit a new comment.
func (p *politeiawww) piCommentNew(ctx context.Context, cn piplugin.CommentNew) (*piplugin.CommentNewReply, error) {
	b, err := piplugin.EncodeCommentNew(cn)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID, piplugin.CmdCommentNew, string(b))
	if err != nil {
		return nil, err
	}
	cnr, err := piplugin.DecodeCommentNewReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cnr, nil
}

// piCommentVote uses the pi plugin to vote on a comment.
func (p *politeiawww) piCommentVote(ctx context.Context, cvp piplugin.CommentVote) (*piplugin.CommentVoteReply, error) {
	b, err := piplugin.EncodeCommentVote(cvp)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID, piplugin.CmdCommentVote, string(b))
	if err != nil {
		return nil, err
	}
	cvr, err := piplugin.DecodeCommentVoteReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cvr, nil
}

// piCommentCensor uses the pi plugin to censor a proposal comment.
func (p *politeiawww) piCommentCensor(ctx context.Context, cc piplugin.CommentCensor) (*piplugin.CommentCensorReply, error) {
	b, err := piplugin.EncodeCommentCensor(cc)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID, piplugin.CmdCommentCensor, string(b))
	if err != nil {
		return nil, err
	}
	ccr, err := piplugin.DecodeCommentCensorReply(([]byte(r)))
	if err != nil {
		return nil, err
	}
	return ccr, nil
}

// piVoteInventory returns the pi plugin vote inventory.
func (p *politeiawww) piVoteInventory(ctx context.Context) (*piplugin.VoteInventoryReply, error) {
	r, err := p.pluginCommand(ctx, piplugin.ID, piplugin.CmdVoteInventory, "")
	if err != nil {
		return nil, err
	}
	vir, err := piplugin.DecodeVoteInventoryReply(([]byte(r)))
	if err != nil {
		return nil, err
	}
	return vir, nil
}
