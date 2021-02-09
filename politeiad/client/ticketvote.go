// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// TicketVoteAuthorize sends the ticketvote plugin Authorize command to the
// politeiad v1 API.
func (c *Client) TicketVoteAuthorize(ctx context.Context, a ticketvote.Authorize) (*ticketvote.AuthorizeReply, error) {
	// Setup request
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   a.Token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdAuthorize,
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
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var ar ticketvote.AuthorizeReply
	err = json.Unmarshal([]byte(pcr.Payload), &ar)
	if err != nil {
		return nil, err
	}

	return &ar, nil
}

// TicketVoteStart sends the ticketvote plugin Start command to the politeiad
// v1 API.
func (c *Client) TicketVoteStart(ctx context.Context, token string, s ticketvote.Start) (*ticketvote.StartReply, error) {
	// Setup request
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdStart,
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
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var sr ticketvote.StartReply
	err = json.Unmarshal([]byte(pcr.Payload), &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteCastBallot sends the ticketvote plugin CastBallot command to the
// politeiad v1 API.
func (c *Client) TicketVoteCastBallot(ctx context.Context, token string, cb ticketvote.CastBallot) (*ticketvote.CastBallotReply, error) {
	// Setup request
	b, err := json.Marshal(cb)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdCastBallot,
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
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var cbr ticketvote.CastBallotReply
	err = json.Unmarshal([]byte(pcr.Payload), &cbr)
	if err != nil {
		return nil, err
	}

	return &cbr, nil
}

// TicketVoteDetails sends the ticketvote plugin Details command to the
// politeiad v1 API.
func (c *Client) TicketVoteDetails(ctx context.Context, token string) (*ticketvote.DetailsReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdDetails,
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
	var dr ticketvote.DetailsReply
	err = json.Unmarshal([]byte(pcr.Payload), &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// TicketVoteResults sends the ticketvote plugin Results command to the
// politeiad v1 API.
func (c *Client) TicketVoteResults(ctx context.Context, token string) (*ticketvote.ResultsReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdResults,
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
	var rr ticketvote.ResultsReply
	err = json.Unmarshal([]byte(pcr.Payload), &rr)
	if err != nil {
		return nil, err
	}

	return &rr, nil
}

// TicketVoteSummary sends the ticketvote plugin Summary command to the
// politeiad v1 API.
func (c *Client) TicketVoteSummary(ctx context.Context, token string) (*ticketvote.SummaryReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdSummary,
			Token:   token,
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
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(pcr.Payload), &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteSummaries sends a batch of ticketvote plugin Summary commands to
// the politeiad v1 API. Individual summary errors are not returned, the token
// will simply be left out of the returned map.
func (c *Client) TicketVoteSummaries(ctx context.Context, tokens []string) (map[string]ticketvote.SummaryReply, error) {
	// Setup request
	cmds := make([]pdv1.PluginCommandV2, 0, len(tokens))
	for _, v := range tokens {
		cmds = append(cmds, pdv1.PluginCommandV2{
			State:   pdv1.RecordStateVetted,
			Token:   v,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdSummary,
			Payload: "",
		})
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	summaries := make(map[string]ticketvote.SummaryReply, len(replies))
	for _, v := range replies {
		err = extractPluginCommandError(v)
		if err != nil {
			// Individual summary errors are ignored. The token will not
			// be included in the returned summaries map.
			continue
		}
		var sr ticketvote.SummaryReply
		err = json.Unmarshal([]byte(v.Payload), &sr)
		if err != nil {
			return nil, err
		}
		summaries[v.Token] = sr
	}

	return summaries, nil
}

// TicketVoteSubmissions sends the ticketvote plugin Submissions command to the
// politeiad v1 API.
func (c *Client) TicketVoteSubmissions(ctx context.Context, token string) (*ticketvote.SubmissionsReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			Token:   token,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdSubmissions,
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
	var sr ticketvote.SubmissionsReply
	err = json.Unmarshal([]byte(pcr.Payload), &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteInventory sends the ticketvote plugin Inventory command to the
// politeiad v1 API.
func (c *Client) TicketVoteInventory(ctx context.Context) (*ticketvote.InventoryReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdInventory,
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
	var ir ticketvote.InventoryReply
	err = json.Unmarshal([]byte(pcr.Payload), &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// TicketVoteTimestamps sends the ticketvote plugin Timestamps command to the
// politeiad v1 API.
func (c *Client) TicketVoteTimestamps(ctx context.Context, token string) (*ticketvote.TimestampsReply, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			State:   pdv1.RecordStateVetted,
			ID:      ticketvote.PluginID,
			Command: ticketvote.CmdTimestamps,
			Token:   token,
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
	var sr ticketvote.TimestampsReply
	err = json.Unmarshal([]byte(pcr.Payload), &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}
