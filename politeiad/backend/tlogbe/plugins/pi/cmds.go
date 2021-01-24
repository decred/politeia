// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTlog, token)
}

func convertPropStatusFromMDStatus(s backend.MDStatusT) pi.PropStatusT {
	var status pi.PropStatusT
	switch s {
	case backend.MDStatusUnvetted, backend.MDStatusIterationUnvetted:
		status = pi.PropStatusUnvetted
	case backend.MDStatusVetted:
		status = pi.PropStatusPublic
	case backend.MDStatusCensored:
		status = pi.PropStatusCensored
	case backend.MDStatusArchived:
		status = pi.PropStatusAbandoned
	}
	return status
}

func (p *piPlugin) cmdProposalInv() (string, error) {
	log.Tracef("cmdProposalInv")

	// Get full record inventory
	ibs, err := p.backend.InventoryByStatus()
	if err != nil {
		return "", err
	}

	// Convert MDStatus keys to human readable proposal statuses
	unvetted := make(map[string][]string, len(ibs.Unvetted))
	vetted := make(map[string][]string, len(ibs.Vetted))
	for k, v := range ibs.Unvetted {
		s := pi.PropStatuses[convertPropStatusFromMDStatus(k)]
		unvetted[s] = v
	}
	for k, v := range ibs.Vetted {
		s := pi.PropStatuses[convertPropStatusFromMDStatus(k)]
		vetted[s] = v
	}

	// Prepare reply
	pir := pi.ProposalInvReply{
		Unvetted: unvetted,
		Vetted:   vetted,
	}
	reply, err := json.Marshal(pir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

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
	approved := make([]string, 0, len(ir.Finished))
	rejected := make([]string, 0, len(ir.Finished))
	for _, v := range ir.Finished {
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
		Unauthorized: ir.Unauthorized,
		Authorized:   ir.Authorized,
		Started:      ir.Started,
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
