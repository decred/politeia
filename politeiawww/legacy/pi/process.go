// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/pi"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/pkg/errors"
)

// processSetBillingStatus processes a pi v1 setbillingstatus request.
func (p *Pi) processSetBillingStatus(ctx context.Context, sbs v1.SetBillingStatus, u user.User) (*v1.SetBillingStatusReply, error) {
	log.Tracef("processSetBillingStatus: %v", sbs.Token)

	// Sanity check
	if !u.Admin {
		return nil, errors.Errorf("user is not an admin")
	}

	// Verify user signed with their active identity
	if u.PublicKey() != sbs.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	psbs := convertSetBillingStatusToPlugin(sbs)
	psbsr, err := p.politeiad.PiSetBillingStatus(ctx, psbs)
	if err != nil {
		return nil, err
	}

	return &v1.SetBillingStatusReply{
		Timestamp: psbsr.Timestamp,
		Receipt:   psbsr.Receipt,
	}, nil
}

// processBillingStatusChanges processes a pi v1 billingstatuschanges request.
func (p *Pi) processBillingStatusChanges(ctx context.Context, bscs v1.BillingStatusChanges) (*v1.BillingStatusChangesReply, error) {
	log.Tracef("processBillingStatusChanges: %v", bscs.Tokens)

	// Verify request size
	if len(bscs.Tokens) > int(v1.BillingStatusChangesPageSize) {
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodePageSizeExceeded,
			ErrorContext: fmt.Sprintf("max page size is %v",
				v1.SummariesPageSize),
		}
	}

	pbscsr, err := p.politeiad.PiBillingStatusChanges(ctx, bscs.Tokens)
	if err != nil {
		return nil, err
	}

	// Convert reply to API.
	billingStatusChangesMap := make(map[string][]v1.BillingStatusChange,
		len(pbscsr))
	// For each token, convert slice of billing status changes.
	for t, bscs := range pbscsr {
		billingStatusChanges := make([]v1.BillingStatusChange, 0,
			len(bscs.BillingStatusChanges))
		for _, bsc := range bscs.BillingStatusChanges {
			billingStatusChanges = append(billingStatusChanges,
				convertBillingStatusChangeToAPI(bsc))
		}
		billingStatusChangesMap[t] = billingStatusChanges
	}

	return &v1.BillingStatusChangesReply{
		BillingStatusChanges: billingStatusChangesMap,
	}, nil
}

// processSummaries processes a pi v1 summaries request.
func (p *Pi) processSummaries(ctx context.Context, s v1.Summaries) (*v1.SummariesReply, error) {
	log.Tracef("processSummaries: %v", s.Tokens)

	// Verify request size
	if len(s.Tokens) > int(v1.SummariesPageSize) {
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodePageSizeExceeded,
			ErrorContext: fmt.Sprintf("max page size is %v",
				v1.SummariesPageSize),
		}
	}

	psr, err := p.politeiad.PiSummaries(ctx, s.Tokens)
	if err != nil {
		return nil, err
	}

	// Convert reply to API
	ss := make(map[string]v1.Summary, len(psr))
	for token, s := range psr {
		ss[token] = v1.Summary{
			Status: string(s.Summary.Status),
		}
	}

	return &v1.SummariesReply{
		Summaries: ss,
	}, nil
}

func convertBillingStatusChangeToAPI(bsc pi.BillingStatusChange) v1.BillingStatusChange {
	return v1.BillingStatusChange{
		Token:     bsc.Token,
		Status:    convertBillingStatusToAPI(bsc.Status),
		Reason:    bsc.Reason,
		PublicKey: bsc.PublicKey,
		Signature: bsc.Signature,
		Receipt:   bsc.Receipt,
		Timestamp: bsc.Timestamp,
	}
}

func convertBillingStatusToAPI(bs pi.BillingStatusT) v1.BillingStatusT {
	switch bs {
	case pi.BillingStatusActive:
		return v1.BillingStatusActive
	case pi.BillingStatusClosed:
		return v1.BillingStatusClosed
	case pi.BillingStatusCompleted:
		return v1.BillingStatusCompleted
	}
	return v1.BillingStatusInvalid
}

func convertSetBillingStatusToPlugin(sbs v1.SetBillingStatus) pi.SetBillingStatus {
	return pi.SetBillingStatus{
		Token:     sbs.Token,
		Status:    convertBillingStatusToPlugin(sbs.Status),
		Reason:    sbs.Reason,
		PublicKey: sbs.PublicKey,
		Signature: sbs.Signature,
	}
}

func convertBillingStatusToPlugin(bs v1.BillingStatusT) pi.BillingStatusT {
	switch bs {
	case v1.BillingStatusActive:
		return pi.BillingStatusActive
	case v1.BillingStatusClosed:
		return pi.BillingStatusClosed
	case v1.BillingStatusCompleted:
		return pi.BillingStatusCompleted
	}
	return pi.BillingStatusInvalid
}
