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
