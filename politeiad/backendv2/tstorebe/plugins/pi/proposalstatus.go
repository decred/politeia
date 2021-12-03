// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/hex"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// getPoposalStatus determines the proposal status at runtime, it uses the
// in-memory cache to avoid retrieving the record, it's vote summary or
// it's billing status changes when possible.
func (p *piPlugin) getProposalStatus(token []byte) (pi.PropStatusT, error) {
	var (
		propStatus pi.PropStatusT
		err        error
		tokenStr   = hex.EncodeToString(token)

		// The following fields are required to determine the proposal status and
		// MUST be populated.
		recordState  backend.StateT
		recordStatus backend.StatusT
		voteStatus   ticketvote.VoteStatusT

		// The following fields are required to determine the proposal status and
		// will only be populated for certain types of proposals or during certain
		// stages of the proposal lifecycle.
		voteMetadata         *ticketvote.VoteMetadata
		billingStatuses      []pi.BillingStatusChange
		billingStatusesCount int

		// Declarations to prevent goto errors
		voteSummary *ticketvote.SummaryReply
	)

	// Check if the proposal status has been cached
	e := p.statuses.get(tokenStr)
	if e != nil {
		propStatus = e.propStatus
		recordState = e.recordState
		recordStatus = e.recordStatus
		voteStatus = e.voteStatus
		voteMetadata = e.voteMetadata
		billingStatusesCount = e.billingStatusesCount
	}

	// Check if we need to get any additional data
	if statusIsFinal(propStatus) {
		// The status is final and cannot be changed.
		// No need to get any additional data.
		return propStatus, nil
	}

	// Get the record if required
	if statusRequiresRecord(propStatus) {
		r, err := p.record(backend.RecordRequest{
			Token:     token,
			Filenames: []string{ticketvote.FileNameVoteMetadata},
		})
		if err != nil {
			return "", err
		}

		// Update the record data fields required to
		// determine the proposal status.
		recordState = r.RecordMetadata.State
		recordStatus = r.RecordMetadata.Status

		// Pull the vote metadata out of the record files
		voteMetadata, err = voteMetadataDecode(r.Files)
		if err != nil {
			return "", err
		}

		// If the proposal is unvetted, no other data is
		// required in order to determine the status.
		if recordState == backend.StateUnvetted {
			goto determineStatus
		}
	}

	// Get the vote summary
	voteSummary, err = p.voteSummary(token)
	if err != nil {
		return "", err
	}
	voteStatus = voteSummary.Status

	// Get the billing statuses if required
	if statusRequiresBillingStatuses(voteStatus) {
		// If the maximum allowed number of billing status changes
		// have already been made for this proposal and those results
		// have been cached, then we don't need to retrieve anything
		// else. The proposal status cannot be changed any further.
		if uint32(billingStatusesCount) >= p.billingStatusChangesMax {
			return propStatus, nil
		}
		billingStatuses, err = p.billingStatusChanges(token)
		if err != nil {
			return "", err
		}
	}

determineStatus:
	// Determine the proposal status
	propStatus, err = proposalStatus(recordState, recordStatus, voteStatus,
		voteMetadata, billingStatuses)
	if err != nil {
		return "", nil
	}

	// Cache the results
	p.statuses.set(tokenStr, statusEntry{
		propStatus:           propStatus,
		recordState:          recordState,
		recordStatus:         recordStatus,
		voteStatus:           voteStatus,
		voteMetadata:         voteMetadata,
		billingStatusesCount: len(billingStatuses),
	})

	return propStatus, nil
}

// statusIsFinal returns whether the proposal status is a final status and
// cannot be changed any further.
func statusIsFinal(s pi.PropStatusT) bool {
	switch s {
	case pi.PropStatusUnvettedAbandoned, pi.PropStatusUnvettedCensored,
		pi.PropStatusAbandoned, pi.PropStatusCensored, pi.PropStatusApproved,
		pi.PropStatusRejected:
		return true
	default:
		return false
	}
}

// statusRequiresRecord returns whether the proposal status requires the record
// to be retrieved from the backend. This is necessary when the proposal is in
// a part of the proposal lifecycle that still allows changes to the underlying
// record data. For example, an unvetted proposal may still have it's record
// metadata or vote metadata altered, but a proposal with the status of active
// cannot.
func statusRequiresRecord(s pi.PropStatusT) bool {
	if statusIsFinal(s) {
		// The status is final and cannot be changed
		// any further, which means the record data
		// is not required.
		return false
	}

	switch s {
	case pi.PropStatusVoteStarted, pi.PropStatusActive,
		pi.PropStatusCompleted, pi.PropStatusClosed:
		// The record cannot be changed any further for
		// these statuses.
		return false

	case pi.PropStatusUnvetted, pi.PropStatusUnderReview,
		pi.PropStatusVoteAuthorized:
		// The record can still change for these statuses.
		return true

	default:
		// Defaulting to true is the conservative default
		// since it will force the record to be retrieved
		// for unhandled cases.
		return true
	}
}

// statusRequiresBillingStatuses returns whether the proposal requires the
// billing status changes to be retrieved. This is necessary when the proposal
// is in a stage where it's billing status can still change.
func statusRequiresBillingStatuses(vs ticketvote.VoteStatusT) bool {
	switch vs {
	case ticketvote.VoteStatusUnauthorized,
		ticketvote.VoteStatusAuthorized,
		ticketvote.VoteStatusStarted,
		ticketvote.VoteStatusFinished,
		ticketvote.VoteStatusRejected,
		ticketvote.VoteStatusIneligible:
		// These vote statuses cannot have billing status
		// changes, so there is not need to retrieve them.
		return false

	case ticketvote.VoteStatusApproved:
		// Approved proposals can have billing status
		// changes. Retrieve them.
		return true

	default:
		// Force the billing statuses to be retrieved for any
		// unhandled cases.
		return true
	}
}
