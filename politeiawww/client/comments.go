// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/util"
)

// CommentsPolicy sends a pi v1 Policy request to politeiawww.
func (c *Client) CommentsPolicy() (*cmv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodGet,
		cmv1.APIRoute, cmv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr cmv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(pr))
	}

	return &pr, nil
}
