// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/util"
)

// PiPolicy sends a pi v1 Policy request to politeiawww.
func (c *Client) PiPolicy() (*piv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodGet,
		piv1.APIRoute, piv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr piv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(pr))
	}

	return &pr, nil
}

// PiProposals sends a pi v1 Proposals request to politeiawww.
func (c *Client) PiProposals(p piv1.Proposals) (*piv1.ProposalsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		piv1.APIRoute, piv1.RouteProposals, p)
	if err != nil {
		return nil, err
	}

	var pr piv1.ProposalsReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(pr))
	}

	return &pr, nil
}
