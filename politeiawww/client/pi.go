// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
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

// PiSetBillingStatus sends a pi v1 SetBillingStatus request
// to politeiawww.
func (c *Client) PiSetBillingStatus(sbs piv1.SetBillingStatus) (*piv1.SetBillingStatusReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		piv1.APIRoute, piv1.RouteSetBillingStatus, sbs)
	if err != nil {
		return nil, err
	}

	var sbsr piv1.SetBillingStatusReply
	err = json.Unmarshal(resBody, &sbsr)
	if err != nil {
		return nil, err
	}

	return &sbsr, nil
}

// PiSummaries sends a pi v1 Summaries request to politeiawww.
func (c *Client) PiSummaries(s piv1.Summaries) (*piv1.SummariesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		piv1.APIRoute, piv1.RouteSummaries, s)
	if err != nil {
		return nil, err
	}

	var sr piv1.SummariesReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// PiBillingStatusChanges sends a pi v1 BillingStatusChanges request to
// politeiawww.
func (c *Client) PiBillingStatusChanges(bscs piv1.BillingStatusChanges) (*piv1.BillingStatusChangesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		piv1.APIRoute, piv1.RouteBillingStatusChanges, bscs)
	if err != nil {
		return nil, err
	}

	var bscsr piv1.BillingStatusChangesReply
	err = json.Unmarshal(resBody, &bscsr)
	if err != nil {
		return nil, err
	}

	return &bscsr, nil
}

// ProposalMetadataDecode decodes and returns the ProposalMetadata from the
// Provided record files. An error returned if a ProposalMetadata is not found.
func ProposalMetadataDecode(files []rcv1.File) (*piv1.ProposalMetadata, error) {
	var pmp *piv1.ProposalMetadata
	for _, v := range files {
		if v.Name != piv1.FileNameProposalMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var pm piv1.ProposalMetadata
		err = json.Unmarshal(b, &pm)
		if err != nil {
			return nil, err
		}
		pmp = &pm
		break
	}
	if pmp == nil {
		return nil, fmt.Errorf("proposal metadata not found")
	}
	return pmp, nil
}

// VoteMetadataDecode decodes and returns the VoteMetadata from the provided
// backend files. Nil is returned if a VoteMetadata is not found.
func VoteMetadataDecode(files []rcv1.File) (*piv1.VoteMetadata, error) {
	var vmp *piv1.VoteMetadata
	for _, v := range files {
		if v.Name != piv1.FileNameVoteMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var vm piv1.VoteMetadata
		err = json.Unmarshal(b, &vm)
		if err != nil {
			return nil, err
		}
		vmp = &vm
		break
	}
	return vmp, nil
}
