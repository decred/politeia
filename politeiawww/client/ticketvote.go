// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"net/http"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// TicketVotePolicy sends a ticketvote v1 Policy request to politeiawww.
func (c *Client) TicketVotePolicy() (*tkv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr tkv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// TicketVoteAuthorize sends a ticketvote v1 Authorize request to politeiawww.
func (c *Client) TicketVoteAuthorize(a tkv1.Authorize) (*tkv1.AuthorizeReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteAuthorize, a)
	if err != nil {
		return nil, err
	}

	var ar tkv1.AuthorizeReply
	err = json.Unmarshal(resBody, &ar)
	if err != nil {
		return nil, err
	}

	return &ar, nil
}

// TicketVoteStart sends a ticketvote v1 Start request to politeiawww.
func (c *Client) TicketVoteStart(s tkv1.Start) (*tkv1.StartReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteStart, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.StartReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteCastBallot sends a ticketvote v1 CastBallot request to
// politeiawww.
func (c *Client) TicketVoteCastBallot(cb tkv1.CastBallot) (*tkv1.CastBallotReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteCastBallot, cb)
	if err != nil {
		return nil, err
	}

	var cbr tkv1.CastBallotReply
	err = json.Unmarshal(resBody, &cbr)
	if err != nil {
		return nil, err
	}

	return &cbr, nil
}

// TicketVoteDetails sends a ticketvote v1 Details request to politeiawww.
func (c *Client) TicketVoteDetails(d tkv1.Details) (*tkv1.DetailsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteDetails, d)
	if err != nil {
		return nil, err
	}

	var dr tkv1.DetailsReply
	err = json.Unmarshal(resBody, &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// TicketVoteResults sends a ticketvote v1 Results request to politeiawww.
func (c *Client) TicketVoteResults(r tkv1.Results) (*tkv1.ResultsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteResults, r)
	if err != nil {
		return nil, err
	}

	var rr tkv1.ResultsReply
	err = json.Unmarshal(resBody, &rr)
	if err != nil {
		return nil, err
	}

	return &rr, nil
}

// TicketVoteSummaries sends a ticketvote v1 Summaries request to politeiawww.
func (c *Client) TicketVoteSummaries(s tkv1.Summaries) (*tkv1.SummariesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteSummaries, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.SummariesReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteSubmissions sends a ticketvote v1 Submissions request to
// politeiawww.
func (c *Client) TicketVoteSubmissions(s tkv1.Submissions) (*tkv1.SubmissionsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteSubmissions, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.SubmissionsReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteInventory sends a ticketvote v1 Inventory request to politeiawww.
func (c *Client) TicketVoteInventory(i tkv1.Inventory) (*tkv1.InventoryReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteInventory, i)
	if err != nil {
		return nil, err
	}

	var ir tkv1.InventoryReply
	err = json.Unmarshal(resBody, &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// TicketVoteTimestamps sends a ticketvote v1 Timestamps request to
// politeiawww.
func (c *Client) TicketVoteTimestamps(t tkv1.Timestamps) (*tkv1.TimestampsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteTimestamps, t)
	if err != nil {
		return nil, err
	}

	var tr tkv1.TimestampsReply
	err = json.Unmarshal(resBody, &tr)
	if err != nil {
		return nil, err
	}

	return &tr, nil
}
