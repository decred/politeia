// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"net/http"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

// RecordNew sends a records v1 New request to politeiawww.
func (c *Client) RecordNew(n rcv1.New) (*rcv1.NewReply, error) {
	route := rcv1.APIRoute + rcv1.RouteNew
	resBody, err := c.makeReq(http.MethodPost, route, n)
	if err != nil {
		return nil, err
	}

	var nr rcv1.NewReply
	err = json.Unmarshal(resBody, &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}
