// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/decred/politeia/politeiad/plugins/pi"
)

// proposalInv returns the pi plugin proposal inventory.
func (p *politeiawww) proposalInv(ctx context.Context, inv pi.ProposalInv) (*pi.ProposalInvReply, error) {
	return nil, nil
}

// piVoteInventory returns the pi plugin vote inventory.
func (p *politeiawww) piVoteInventory(ctx context.Context) (*pi.VoteInventoryReply, error) {
	return nil, nil
}
