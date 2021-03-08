// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// Author sends the user plugin Author command to the politeiad v2 API.
func (c *Client) Author(ctx context.Context, token string) (string, error) {
	// Setup request
	cmds := []pdv2.PluginCmd{
		{
			Token:   token,
			ID:      usermd.PluginID,
			Command: usermd.CmdAuthor,
			Payload: "",
		},
	}

	// Send request
	replies, err := c.PluginReads(ctx, cmds)
	if err != nil {
		return "", err
	}
	if len(replies) == 0 {
		return "", fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCmdError(pcr)
	if err != nil {
		return "", err
	}

	// Decode reply
	var ar usermd.AuthorReply
	err = json.Unmarshal([]byte(pcr.Payload), &ar)
	if err != nil {
		return "", err
	}

	return ar.UserID, nil
}

// UserRecords sends the user plugin UserRecords command to the politeiad v2
// API.
func (c *Client) UserRecords(ctx context.Context, userID string) (*usermd.UserRecordsReply, error) {
	// Setup request
	ur := usermd.UserRecords{
		UserID: userID,
	}
	b, err := json.Marshal(ur)
	if err != nil {
		return nil, err
	}
	cmds := []pdv2.PluginCmd{
		{
			ID:      usermd.PluginID,
			Command: usermd.CmdUserRecords,
			Payload: string(b),
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
	var urr usermd.UserRecordsReply
	err = json.Unmarshal([]byte(pcr.Payload), &urr)
	if err != nil {
		return nil, err
	}

	return &urr, nil
}
