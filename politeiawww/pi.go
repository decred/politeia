// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/decred/politeia/politeiad/plugins/pi"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
)

// piPassThrough executes the pi plugin PassThrough command.
func (p *politeiawww) piPassThrough(ctx context.Context, pt pi.PassThrough) (*pi.PassThroughReply, error) {
	b, err := piplugin.EncodePassThrough(pt)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID,
		piplugin.CmdPassThrough, string(b))
	if err != nil {
		return nil, err
	}
	ptr, err := piplugin.DecodePassThroughReply(([]byte(r)))
	if err != nil {
		return nil, err
	}
	return ptr, nil
}

// piProposals returns the pi plugin data for the provided proposals.
func (p *politeiawww) piProposals(ctx context.Context, ps piplugin.Proposals) (*piplugin.ProposalsReply, error) {
	b, err := piplugin.EncodeProposals(ps)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID,
		piplugin.CmdProposals, string(b))
	if err != nil {
		return nil, err
	}
	pr, err := piplugin.DecodeProposalsReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return pr, nil
}

// proposalInv returns the pi plugin proposal inventory.
func (p *politeiawww) proposalInv(ctx context.Context, inv piplugin.ProposalInv) (*piplugin.ProposalInvReply, error) {
	b, err := piplugin.EncodeProposalInv(inv)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, piplugin.ID,
		piplugin.CmdProposalInv, string(b))
	if err != nil {
		return nil, err
	}
	reply, err := piplugin.DecodeProposalInvReply(([]byte(r)))
	if err != nil {
		return nil, err
	}
	return reply, nil
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
