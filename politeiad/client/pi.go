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

// PiSetBillingStatus sends the pi plugin SetBillingStatus command to the
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

// PiSummaries sends a page of pi plugin Summary commands to the politeiad
// v2 API.
func (c *Client) PiSummaries(ctx context.Context, tokens []string) (map[string]pi.SummaryReply, error) {
	// Setup request
	cmds := make([]pdv2.PluginCmd, 0, len(tokens))
	for _, t := range tokens {
		cmds = append(cmds, pdv2.PluginCmd{
			Token:   t,
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
	ssr := make(map[string]pi.SummaryReply, len(replies))
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
		ssr[v.Token] = sr
	}

	return ssr, nil
}

// PiBillingStatusChanges sends a page of pi plugin BillingStatusChanges
// commands to the politeiad v2 API.
func (c *Client) PiBillingStatusChanges(ctx context.Context, tokens []string) (map[string]pi.BillingStatusChangesReply, error) {
	// Setup request
	cmds := make([]pdv2.PluginCmd, 0, len(tokens))
	for _, t := range tokens {
		cmds = append(cmds, pdv2.PluginCmd{
			Token:   t,
			ID:      pi.PluginID,
			Command: pi.CmdBillingStatusChanges,
			Payload: "",
		})
	}

	// Send request
	replies, err := c.PluginReads(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	bscsr := make(map[string]pi.BillingStatusChangesReply, len(replies))
	for _, v := range replies {
		err = extractPluginCmdError(v)
		if err != nil {
			// Individual summary errors are ignored. The token will not
			// be included in the returned summaries map.
			continue
		}
		var bscr pi.BillingStatusChangesReply
		err = json.Unmarshal([]byte(v.Payload), &bscr)
		if err != nil {
			return nil, err
		}
		bscsr[v.Token] = bscr
	}

	return bscsr, nil

}
