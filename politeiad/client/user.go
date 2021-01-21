// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/user"
)

// Author sends the user plugin Author command to the politeiad v1 API.
func (c *Client) Author(ctx context.Context, state, token string) (string, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      user.PluginID,
			Command: user.CmdAuthor,
			Payload: "",
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return "", err
	}

	// Decode reply
	if len(replies) == 0 {
		return "", fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	if pcr.Error != nil {
		return "", pcr.Error
	}
	var ar user.AuthorReply
	err = json.Unmarshal([]byte(pcr.Payload), &ar)
	if err != nil {
		return "", err
	}

	return ar.UserID, nil
}

// UserRecords sends the user plugin UserRecords command to the politeiad v1
// API.
func (c *Client) UserRecords(ctx context.Context, state, token, userID string) ([]string, error) {
	// Setup request
	ur := user.UserRecords{
		UserID: userID,
	}
	b, err := json.Marshal(ur)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   state,
			Token:   token,
			ID:      user.PluginID,
			Command: user.CmdUserRecords,
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
	var urr user.UserRecordsReply
	err = json.Unmarshal([]byte(pcr.Payload), &urr)
	if err != nil {
		return nil, err
	}

	return urr.Records, nil
}
