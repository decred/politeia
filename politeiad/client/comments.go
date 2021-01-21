// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/comments"
)

func (c *Client) CommentNew(ctx context.Context, state, token string, n comments.New) (*comments.NewReply, error) {
	// Setup request
	b, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdNew,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Decode reply
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	if pcr.Error != nil {
		return nil, pcr.Error
	}
	var nr comments.NewReply
	err = json.Unmarshal([]byte(pcr.Payload), &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

func (c *Client) CommentVote(ctx context.Context, state, token string, v comments.Vote) (*comments.VoteReply, error) {
	// Setup request
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdVote,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Decode reply
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	if pcr.Error != nil {
		return nil, pcr.Error
	}
	var nr comments.VoteReply
	err = json.Unmarshal([]byte(pcr.Payload), &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}
