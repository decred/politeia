// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/pi"
)

// PiVoteInv sends the pi plugin VoteInv command to the politeiad v1 API.
func (c *Client) PiVoteInv(ctx context.Context) (*pi.VoteInventoryReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   "",
			ID:      pi.PluginID,
			Command: pi.CmdVoteInv,
			Payload: "",
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var vir pi.VoteInventoryReply
	err = json.Unmarshal([]byte(pcr.Payload), &vir)
	if err != nil {
		return nil, err
	}

	return &vir, nil
}
