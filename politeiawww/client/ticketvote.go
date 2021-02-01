// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"net/http"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// TicketVotePolicy sends a pi v1 Policy request to politeiawww.
func (c *Client) TicketVotePolicy() (*tkv1.PolicyReply, error) {
	route := tkv1.APIRoute + tkv1.RoutePolicy
	resBody, err := c.makeReq(http.MethodGet, route, nil)
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
