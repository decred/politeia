// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/plugins/pi"
)

// PiSummaries sends a page of pi plugin Summary commands to the politeiad
// v2 API.
func (c *Client) PiSummaries(ctx context.Context, s pi.Summaries) (*pi.SummariesReply, error) {
	// Setup request
	cmds := make([]pdv2.PluginCmd, 0, len(s.Tokens))
	for _, v := range s.Tokens {
		cmds = append(cmds, pdv2.PluginCmd{
			Token:   v,
			ID:      pi.PluginID,
			Command: pi.CmdSummary,
			Payload: "",
		})
	}

	// Send request
	replies, err := c.PluginReads(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	ssr := pi.SummariesReply{}
	ssr.Summaries = make(map[string]pi.ProposalSummary, len(replies))
	for _, v := range replies {
		err = extractPluginCmdError(v)
		if err != nil {
			// Individual summary errors are ignored. The token will not
			// be included in the returned summaries map.
			continue
		}
		var sr pi.SummaryReply
		err = json.Unmarshal([]byte(v.Payload), &sr)
		if err != nil {
			return nil, err
		}
		ssr.Summaries[v.Token] = sr.Summary
	}

	return &ssr, nil
}

// PiSetBillingStatus sends the pi plugin BillingStatus command to the
// politeiad v2 API.
func (c *Client) PiSetBillingStatus(ctx context.Context, sbs pi.SetBillingStatus) (*pi.SetBillingStatusReply, error) {
	// Setup request
	b, err := json.Marshal(sbs)
	if err != nil {
		return nil, err
	}
	cmd := pdv2.PluginCmd{
		Token:   sbs.Token,
		ID:      pi.PluginID,
		Command: pi.CmdSetBillingStatus,
		Payload: string(b),
	}

	// Send request
	reply, err := c.PluginWrite(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var sbsr pi.SetBillingStatusReply
	err = json.Unmarshal([]byte(reply), &sbsr)
	if err != nil {
		return nil, err
	}

	return &sbsr, nil
}
