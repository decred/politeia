// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"

	"github.com/decred/politeia/politeiad/plugins/pi"
)

// proposalInv returns the pi plugin proposal inventory.
func (p *politeiawww) proposalInv(ctx context.Context, inv pi.ProposalInv) (*pi.ProposalInvReply, error) {
	b, err := json.Marshal(inv)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, pi.ID,
		pi.CmdProposalInv, string(b))
	if err != nil {
		return nil, err
	}
	var ir pi.ProposalInvReply
	err = json.Unmarshal([]byte(r), &ir)
	if err != nil {
		return nil, err
	}
	return &ir, nil
}

// piVoteInventory returns the pi plugin vote inventory.
func (p *politeiawww) piVoteInventory(ctx context.Context) (*pi.VoteInventoryReply, error) {
	r, err := p.pluginCommand(ctx, pi.ID, pi.CmdVoteInventory, "")
	if err != nil {
		return nil, err
	}
	var vir pi.VoteInventoryReply
	err = json.Unmarshal([]byte(r), &vir)
	if err != nil {
		return nil, err
	}
	return &vir, nil
}
