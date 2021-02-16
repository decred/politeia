// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// Author sends the user plugin Author command to the politeiad v1 API.
func (c *Client) Author(ctx context.Context, state, token string) (string, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   token,
			ID:      usermd.PluginID,
			Command: usermd.CmdAuthor,
			Payload: "",
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return "", err
	}
	if len(replies) == 0 {
		return "", fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
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

// UserRecords sends the user plugin UserRecords command to the politeiad v1
// API. A seperate command is sent for the unvetted and vetted records. The
// returned map is a map[recordState][]token.
func (c *Client) UserRecords(ctx context.Context, userID string) (map[string][]string, error) {
	// Setup request
	ur := usermd.UserRecords{
		UserID: userID,
	}
	b, err := json.Marshal(ur)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   pdv1.RecordStateUnvetted,
			ID:      usermd.PluginID,
			Command: usermd.CmdUserRecords,
			Payload: string(b),
		},
		{
			State:   pdv1.RecordStateVetted,
			ID:      usermd.PluginID,
			Command: usermd.CmdUserRecords,
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

	// Decode replies
	reply := make(map[string][]string, 2) // [recordState][]token
	for _, v := range replies {
		err = extractPluginCommandError(v)
		if err != nil {
			// Swallow individual errors
			continue
		}
		var urr usermd.UserRecordsReply
		err = json.Unmarshal([]byte(v.Payload), &urr)
		if err != nil {
			return nil, err
		}
		reply[v.State] = urr.Records
	}

	return reply, nil
}
