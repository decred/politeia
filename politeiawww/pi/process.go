// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	tvv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func (p *Pi) processSetBillingStatus(ctx context.Context, sbs piv1.SetBillingStatus, u user.User) (*piv1.SetBillingStatusReply, error) {
	log.Tracef("processSetBillingStatus: %v", sbs.Token)

	// Verify user signed with their active identity
	if u.PublicKey() != sbs.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Ensure record's vote ended and it was approved
	tvsr, err := p.politeiad.TicketVoteSummary(ctx, sbs.Token)
	voteStatus := convertVoteStatusToV1(tvsr.Status)
	if voteStatus != tvv1.VoteStatusApproved {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorCodeRecordNotApproved,
			ErrorContext: "setting billing status is allowed only if " +
				"record was approved",
		}
	}

	// Send plugin command
	psbs := convertSetBillingStatusToPlugin(sbs)
	psbsr, err := p.politeiad.PiSetBillingStatus(ctx, psbs)
	if err != nil {
		return nil, err
	}

	return &piv1.SetBillingStatusReply{
		Timestamp: psbsr.Timestamp,
		Receipt:   psbsr.Receipt,
	}, nil
}

func convertVoteStatusToV1(s ticketvote.VoteStatusT) tvv1.VoteStatusT {
	switch s {
	case ticketvote.VoteStatusInvalid:
		return tvv1.VoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return tvv1.VoteStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		return tvv1.VoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return tvv1.VoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return tvv1.VoteStatusFinished
	case ticketvote.VoteStatusApproved:
		return tvv1.VoteStatusApproved
	case ticketvote.VoteStatusRejected:
		return tvv1.VoteStatusRejected
	default:
		return tvv1.VoteStatusInvalid
	}
}

func convertSetBillingStatusToPlugin(sbs piv1.SetBillingStatus) pi.SetBillingStatus {
	return pi.SetBillingStatus{
		Token:     sbs.Token,
		Status:    convertBillingStatusToPlugin(sbs.Status),
		Reason:    sbs.Reason,
		PublicKey: sbs.PublicKey,
		Signature: sbs.Signature,
	}
}

func convertBillingStatusToPlugin(bs piv1.BillingStatusT) pi.BillingStatusT {
	switch bs {
	case piv1.BillingStatusClosed:
		return pi.BillingStatusClosed
	case piv1.BillingStatusCompleted:
		return pi.BillingStatusCompleted
	}
	return pi.BillingStatusInvalid
}
