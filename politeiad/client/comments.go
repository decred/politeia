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

// CommentNew sends the comments plugin New command to the politeiad v1 API.
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
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	if pcr.Error != nil {
		return nil, pcr.Error
	}

	// Decode reply
	var nr comments.NewReply
	err = json.Unmarshal([]byte(pcr.Payload), &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

// CommentVote sends the comments plugin Vote command to the politeiad v1 API.
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
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	if pcr.Error != nil {
		return nil, pcr.Error
	}

	// Decode reply
	var nr comments.VoteReply
	err = json.Unmarshal([]byte(pcr.Payload), &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

// CommentDel sends the comments plugin Del command to the politeiad v1 API.
func (c *Client) CommentDel(ctx context.Context, state, token string, d comments.Del) (*comments.DelReply, error) {
	// Setup request
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdDel,
			Payload: string(b),
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

	// Decode reply
	pcr := replies[0]
	if pcr.Error != nil {
		return nil, pcr.Error
	}
	var dr comments.DelReply
	err = json.Unmarshal([]byte(pcr.Payload), &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// CommentCounts sends a batch of comment plugin Count commands to the
// politeiad v1 API and returns a map[token]count with the results. If a record
// is not found for a token or any other error occurs, that token will not be
// included in the reply.
func (c *Client) CommentCounts(ctx context.Context, state string, tokens []string) (map[string]uint32, error) {
	// Setup request
	cmds := make([]pdv1.PluginCommandV2, 0, len(tokens))
	for _, v := range tokens {
		cmds = append(cmds, pdv1.PluginCommandV2{
			State:   state,
			Token:   v,
			ID:      comments.PluginID,
			Command: comments.CmdCount,
		})
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == len(cmds) {
		return nil, fmt.Errorf("replies missing")
	}

	// Decode replies
	counts := make(map[string]uint32, len(replies))
	for _, v := range replies {
		// This command swallows individual errors. The token of the
		// command that errored will not be included in the reply.
		if v.Error != nil {
			continue
		}
		var cr comments.CountReply
		err = json.Unmarshal([]byte(v.Payload), cr)
		if err != nil {
			continue
		}
		counts[v.Token] = cr.Count
	}

	return counts, nil
}

// CommentGetAll sends the comments plugin GetAll command to the politeiad v1
// API.
func (c *Client) CommentGetAll(ctx context.Context, state, token string) ([]comments.Comment, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdGetAll,
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
	if pcr.Error != nil {
		return nil, pcr.Error
	}

	// Decode reply
	var gar comments.GetAllReply
	err = json.Unmarshal([]byte(pcr.Payload), &gar)
	if err != nil {
		return nil, err
	}

	return gar.Comments, nil
}

// CommentVotes sends the comments plugin Votes command to the politeiad v1
// API.
func (c *Client) CommentVotes(ctx context.Context, state, token, userID string) ([]comments.CommentVote, error) {
	// Setup request
	cm := comments.Votes{
		UserID: userID,
	}
	b, err := json.Marshal(cm)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdVotes,
			Payload: string(b),
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
	if pcr.Error != nil {
		return nil, pcr.Error
	}

	// Decode reply
	var vr comments.VotesReply
	err = json.Unmarshal([]byte(pcr.Payload), &vr)
	if err != nil {
		return nil, err
	}

	return vr.Votes, nil
}
