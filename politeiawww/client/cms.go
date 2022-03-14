// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	cmsv2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

// CmsPolicy sends a cms v2 Policy request to politeiawww.
func (c *Client) CmsPolicy() (*cmsv2.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmsv2.APIRoute, cmsv2.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr cmsv2.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// CmsSetInvoiceStatus sends a cms v1 SetInvoiceStatus request
// to politeiawww.
func (c *Client) CmsSetInvoiceStatus(sbs cmsv2.SetInvoiceStatus) (*cmsv2.SetInvoiceStatusReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmsv2.APIRoute, cmsv2.RouteSetInvoiceStatus, sbs)
	if err != nil {
		return nil, err
	}

	var sbsr cmsv2.SetInvoiceStatusReply
	err = json.Unmarshal(resBody, &sbsr)
	if err != nil {
		return nil, err
	}

	return &sbsr, nil
}

// CmsSummaries sends a cms v1 Summaries request to politeiawww.
func (c *Client) CmsSummaries(s cmsv2.Summaries) (*cmsv2.SummariesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmsv2.APIRoute, cmsv2.RouteSummaries, s)
	if err != nil {
		return nil, err
	}

	var sr cmsv2.SummariesReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// CmsInvoiceStatusChanges sends a cms v1 InvoiceStatusChanges request to
// politeiawww.
func (c *Client) CmsInvoiceStatusChanges(bscs cmsv2.InvoiceStatusChanges) (*cmsv2.InvoiceStatusChangesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmsv2.APIRoute, cmsv2.RouteInvoiceStatusChanges, bscs)
	if err != nil {
		return nil, err
	}

	var bscsr cmsv2.InvoiceStatusChangesReply
	err = json.Unmarshal(resBody, &bscsr)
	if err != nil {
		return nil, err
	}

	return &bscsr, nil
}

// InvoiceMetadataDecode decodes and returns the InvoiceMetadata from the
// Provided record files. An error returned if a InvoiceMetadata is not found.
func InvoiceMetadataDecode(files []rcv1.File) (*cmsv2.InvoiceMetadata, error) {
	var pmp *cmsv2.InvoiceMetadata
	for _, v := range files {
		if v.Name != cmsv2.FileNameInvoiceMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var pm cmsv2.InvoiceMetadata
		err = json.Unmarshal(b, &pm)
		if err != nil {
			return nil, err
		}
		pmp = &pm
		break
	}
	if pmp == nil {
		return nil, fmt.Errorf("invoice metadata not found")
	}
	return pmp, nil
}
