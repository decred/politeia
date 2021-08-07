// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"

	"github.com/decred/politeia/politeiad/plugins/pi"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func (p *Pi) processSetBillingStatus(ctx context.Context, sbs v1.SetBillingStatus, u user.User) (*v1.SetBillingStatusReply, error) {
	log.Tracef("processSetBillingStatus: %v", sbs.Token)

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
	case v1.BillingStatusClosed:
		return pi.BillingStatusClosed
	case v1.BillingStatusCompleted:
		return pi.BillingStatusCompleted
	}
	return pi.BillingStatusInvalid
}
