// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"context"
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/cms"
	v2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/pkg/errors"
)

// processSetInvoiceStatus processes a cms v2 setinvoicestatus request.
func (c *Cms) processSetInvoiceStatus(ctx context.Context, sbs v2.SetInvoiceStatus, u user.User) (*v2.SetInvoiceStatusReply, error) {
	log.Tracef("processSetInvoiceStatus: %v", sbs.Token)

	// Sanity check
	if !u.Admin {
		return nil, errors.Errorf("user is not an admin")
	}

	// Verify user signed with their active identity
	if u.PublicKey() != sbs.PublicKey {
		return nil, v2.UserErrorReply{
			ErrorCode:    v2.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	psbs := convertSetInvoiceStatusToPlugin(sbs)
	psbsr, err := c.politeiad.CmsSetInvoiceStatus(ctx, psbs)
	if err != nil {
		return nil, err
	}

	// Emit event
	c.events.Emit(EventTypeInvoiceStatusUpdated,
		EventInvoiceStatusUpdated{
			Token: sbs.Token,
			Email: u.Email,
		})

	return &v2.SetInvoiceStatusReply{
		Timestamp: psbsr.Timestamp,
		Receipt:   psbsr.Receipt,
	}, nil
}

// processSummaries processes a cms v2 summaries request.
func (c *Cms) processSummaries(ctx context.Context, s v2.Summaries) (*v2.SummariesReply, error) {
	log.Tracef("processSummaries: %v", s.Tokens)

	// Verify request size
	if len(s.Tokens) > int(v2.SummariesPageSize) {
		return nil, v2.UserErrorReply{
			ErrorCode: v2.ErrorCodePageSizeExceeded,
			ErrorContext: fmt.Sprintf("max page size is %v",
				v2.SummariesPageSize),
		}
	}

	psr, err := c.politeiad.CmsSummaries(ctx, s.Tokens)
	if err != nil {
		return nil, err
	}

	// Convert reply to API
	ss := make(map[string]v2.Summary, len(psr))
	for token, s := range psr {
		ss[token] = v2.Summary{
			Status: string(s.Summary.Status),
		}
	}

	return &v2.SummariesReply{
		Summaries: ss,
	}, nil
}

// processInvoiceStatusChanges processes a cms v2 invoicestatuschanges request.
func (c *Cms) processInvoiceStatusChanges(ctx context.Context, bscs v2.InvoiceStatusChanges) (*v2.InvoiceStatusChangesReply, error) {
	log.Tracef("processInvoiceStatusChanges: %v", bscs.Token)

	pbscsr, err := c.politeiad.CmsInvoiceStatusChanges(ctx, bscs.Token)
	if err != nil {
		return nil, err
	}

	// Convert reply to API.
	invoiceStatusChanges := make([]v2.InvoiceStatusChange, 0,
		len(pbscsr.InvoiceStatusChanges))
	for _, bsc := range pbscsr.InvoiceStatusChanges {
		invoiceStatusChanges = append(invoiceStatusChanges,
			convertInvoiceStatusChangeToAPI(bsc))
	}

	return &v2.InvoiceStatusChangesReply{
		InvoiceStatusChanges: invoiceStatusChanges,
	}, nil
}

func convertInvoiceStatusChangeToAPI(bsc cms.InvoiceStatusChange) v2.InvoiceStatusChange {
	return v2.InvoiceStatusChange{
		Token:     bsc.Token,
		Status:    convertInvoiceStatusToAPI(bsc.Status),
		Reason:    bsc.Reason,
		PublicKey: bsc.PublicKey,
		Signature: bsc.Signature,
		Receipt:   bsc.Receipt,
		Timestamp: bsc.Timestamp,
	}
}

func convertInvoiceStatusToAPI(bs cms.InvoiceStatusT) v2.InvoiceStatusT {
	switch bs {
	case cms.InvoiceStatusNotFound:
		return v2.InvoiceStatusNotFound
	case cms.InvoiceStatusNew:
		return v2.InvoiceStatusNew
	case cms.InvoiceStatusUpdated:
		return v2.InvoiceStatusUpdated
	case cms.InvoiceStatusApproved:
		return v2.InvoiceStatusApproved
	case cms.InvoiceStatusDisputed:
		return v2.InvoiceStatusDisputed
	case cms.InvoiceStatusRejected:
		return v2.InvoiceStatusRejected
	case cms.InvoiceStatusPaid:
		return v2.InvoiceStatusPaid
	}
	return v2.InvoiceStatusInvalid
}

func convertSetInvoiceStatusToPlugin(sbs v2.SetInvoiceStatus) cms.SetInvoiceStatus {
	return cms.SetInvoiceStatus{
		Token:     sbs.Token,
		Status:    convertInvoiceStatusToPlugin(sbs.Status),
		Reason:    sbs.Reason,
		PublicKey: sbs.PublicKey,
		Signature: sbs.Signature,
	}
}

func convertInvoiceStatusToPlugin(bs v2.InvoiceStatusT) cms.InvoiceStatusT {
	switch bs {
	case v2.InvoiceStatusNotFound:
		return cms.InvoiceStatusNotFound
	case v2.InvoiceStatusNew:
		return cms.InvoiceStatusNew
	case v2.InvoiceStatusUpdated:
		return cms.InvoiceStatusUpdated
	case v2.InvoiceStatusApproved:
		return cms.InvoiceStatusApproved
	case v2.InvoiceStatusDisputed:
		return cms.InvoiceStatusDisputed
	case v2.InvoiceStatusRejected:
		return cms.InvoiceStatusRejected
	case v2.InvoiceStatusPaid:
		return cms.InvoiceStatusPaid
	}
	return cms.InvoiceStatusInvalid
}
