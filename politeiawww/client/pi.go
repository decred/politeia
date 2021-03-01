// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"net/http"

	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
)

// PiPolicy sends a pi v1 Policy request to politeiawww.
func (c *Client) PiPolicy() (*piv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		piv1.APIRoute, piv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr piv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}
