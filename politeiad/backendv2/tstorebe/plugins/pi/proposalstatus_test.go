// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"testing"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

func TestProposalStatus(t *testing.T) {
	// Setup tests
	var tests = []struct {
		name           string // Test name
		state          backend.StateT
		status         backend.StatusT
		voteStatus     ticketvote.VoteStatusT
		voteMD         *ticketvote.VoteMetadata
		bscs           []pi.BillingStatusChange
		proposalStatus pi.PropStatusT // Expected proposal status
	}{
		{
			"unvetted",
			backend.StateUnvetted,
			backend.StatusUnreviewed,
			ticketvote.VoteStatusInvalid,
			nil,
			nil,
			pi.PropStatusUnvetted,
		},
		{
			"unvetted-censored",
			backend.StateUnvetted,
			backend.StatusCensored,
			ticketvote.VoteStatusInvalid,
			nil,
			nil,
			pi.PropStatusUnvettedCensored,
		},
		{
			"unvetted-abandoned",
			backend.StateUnvetted,
			backend.StatusArchived,
			ticketvote.VoteStatusInvalid,
			nil,
			nil,
			pi.PropStatusUnvettedAbandoned,
		},
		{
			"abandoned",
			backend.StateVetted,
			backend.StatusArchived,
			ticketvote.VoteStatusInvalid,
			nil,
			nil,
			pi.PropStatusAbandoned,
		},
		{
			"censored",
			backend.StateVetted,
			backend.StatusCensored,
			ticketvote.VoteStatusInvalid,
			nil,
			nil,
			pi.PropStatusCensored,
		},
		{
			"under-review",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusUnauthorized,
			nil,
			nil,
			pi.PropStatusUnderReview,
		},
		{
			"vote-authorized",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusAuthorized,
			nil,
			nil,
			pi.PropStatusVoteAuthorized,
		},
		{
			"vote-started",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusStarted,
			nil,
			nil,
			pi.PropStatusVoteStarted,
		},
		{
			"approved",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusApproved,
			&ticketvote.VoteMetadata{
				LinkBy: time.Now().Unix() + 600, // 10m in the future
			},
			nil,
			pi.PropStatusApproved,
		},
		{
			"closed",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusApproved,
			nil,
			[]pi.BillingStatusChange{
				{
					Status: pi.BillingStatusClosed,
				},
			},
			pi.PropStatusClosed,
		},
		{
			"completed",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusApproved,
			nil,
			[]pi.BillingStatusChange{
				{
					Status: pi.BillingStatusCompleted,
				},
			},
			pi.PropStatusCompleted,
		},
		{
			"multi_active",
			backend.StateVetted,
			backend.StatusPublic,
			ticketvote.VoteStatusApproved,
			nil,
			[]pi.BillingStatusChange{
				{
					Status: pi.BillingStatusCompleted,
				},
				{
					Status: pi.BillingStatusActive,
				},
			},
			pi.PropStatusActive,
		},
		{
			"invalid",
			backend.StateUnvetted,
			backend.StatusPublic,
			ticketvote.VoteStatusApproved,
			nil,
			nil,
			pi.PropStatusInvalid,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Run test
			status, _ := proposalStatus(tc.state, tc.status,
				tc.voteStatus, tc.voteMD, tc.bscs)

			// Check if received proposal status euqal to the expected.
			if tc.proposalStatus != status {
				t.Errorf("want proposal status %v, got '%v'", tc.proposalStatus,
					status)
			}
		})
	}
}
