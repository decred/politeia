// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

func (p *piPlugin) voteSummary(token []byte) (*ticketvote.SummaryReply, error) {
	reply, err := p.backend.VettedPluginCmd(token,
		ticketvote.PluginID, ticketvote.CmdSummary, "")
	if err != nil {
		return nil, err
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(reply), &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

func (p *piPlugin) cmdVoteInv() (string, error) {
	// Get ticketvote inventory
	r, err := p.backend.VettedPluginCmd([]byte{},
		ticketvote.PluginID, ticketvote.CmdInventory, "")
	if err != nil {
		return "", fmt.Errorf("VettedPluginCmd %v %v: %v",
			ticketvote.PluginID, ticketvote.CmdInventory, err)
	}
	var ir ticketvote.InventoryReply
	err = json.Unmarshal([]byte(r), &ir)
	if err != nil {
		return "", err
	}

	// Get vote summaries for all finished proposal votes and
	// categorize by approved/rejected.
	var (
		finished = ir.Records[ticketvote.VoteStatusFinished]
		approved = make([]string, 0, len(finished))
		rejected = make([]string, 0, len(finished))
	)
	for _, v := range finished {
		t, err := tokenDecode(v)
		if err != nil {
			return "", err
		}
		vs, err := p.voteSummary(t)
		if err != nil {
			return "", err
		}
		if vs.Approved {
			approved = append(approved, v)
		} else {
			rejected = append(rejected, v)
		}
	}

	// Prepare reply
	vir := pi.VoteInventoryReply{
		Unauthorized: ir.Records[ticketvote.VoteStatusUnauthorized],
		Authorized:   ir.Records[ticketvote.VoteStatusAuthorized],
		Started:      ir.Records[ticketvote.VoteStatusStarted],
		Approved:     approved,
		Rejected:     rejected,
		BestBlock:    ir.BestBlock,
	}
	reply, err := json.Marshal(vir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}
