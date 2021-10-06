// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/plugins/cms"
)

// CmsSetInvoiceStatus sends the cms plugin SetInvoiceStatus command to the
// politeiad v2 API.
func (c *Client) CmsSetInvoiceStatus(ctx context.Context, sbs cms.SetInvoiceStatus) (*cms.SetInvoiceStatusReply, error) {
	// Setup request
	b, err := json.Marshal(sbs)
	if err != nil {
		return nil, err
	}
	cmd := pdv2.PluginCmd{
		Token:   sbs.Token,
		ID:      cms.PluginID,
		Command: cms.CmdSetInvoiceStatus,
		Payload: string(b),
	}

	// Send request
	reply, err := c.PluginWrite(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var sbsr cms.SetInvoiceStatusReply
	err = json.Unmarshal([]byte(reply), &sbsr)
	if err != nil {
		return nil, err
	}

	return &sbsr, nil
}

// CmsSummaries sends a page of cms plugin Summary commands to the politeiad
// v2 API.
func (c *Client) CmsSummaries(ctx context.Context, tokens []string) (map[string]cms.SummaryReply, error) {
	// Setup request
	cmds := make([]pdv2.PluginCmd, 0, len(tokens))
	for _, v := range tokens {
		cmds = append(cmds, pdv2.PluginCmd{
			Token:   v,
			ID:      cms.PluginID,
			Command: cms.CmdSummary,
			Payload: "",
		})
	}

	// Send request
	replies, err := c.PluginReads(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	ssr := make(map[string]cms.SummaryReply, len(replies))
	for _, v := range replies {
		err = extractPluginCmdError(v)
		if err != nil {
			// Individual summary errors are ignored. The token will not
			// be included in the returned summaries map.
			continue
		}
		var sr cms.SummaryReply
		err = json.Unmarshal([]byte(v.Payload), &sr)
		if err != nil {
			return nil, err
		}
		ssr[v.Token] = sr
	}

	return ssr, nil
}

// CmsInvoiceStatusChanges sends the cms plugin InvoiceStatusChanges command
// to the politeiad v2 API.
func (c *Client) CmsInvoiceStatusChanges(ctx context.Context, token string) (*cms.InvoiceStatusChangesReply, error) {
	// Setup request
	cmds := []pdv2.PluginCmd{
		{
			Token:   token,
			ID:      cms.PluginID,
			Command: cms.CmdInvoiceStatusChanges,
			Payload: "",
		},
	}

	// Send request
	replies, err := c.PluginReads(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCmdError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var bscsr cms.InvoiceStatusChangesReply
	err = json.Unmarshal([]byte(pcr.Payload), &bscsr)
	if err != nil {
		return nil, err
	}

	return &bscsr, nil

}
