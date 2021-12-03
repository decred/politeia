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
		voteMetadata    *ticketvote.VoteMetadata
		billingStatuses []pi.BillingStatusChange
	)

	// Check if the proposal status has been cached
	e := p.statuses.get(tokenStr)
	if e != nil {
		propStatus = e.propStatus
		recordState = e.recordState
		recordStatus = e.recordStatus
		voteStatus = e.voteStatus
		voteMetadata = e.voteMetadata
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
		voteStatus = ticketvote.VoteStatusInvalid

		// Pull the vote metadata out of the record files
		voteMetadata, err = voteMetadataDecode(r.Files)
		if err != nil {
			return "", err
		}
	}

	// Get the vote summary if required
	if statusRequiresVoteSummary(propStatus) {
		vs, err := p.voteSummary(token)
		if err != nil {
			return "", err
		}
		voteStatus = vs.Status
	}

	// Get the billing statuses if required
	if statusRequiresBillingStatuses(propStatus) {
		billingStatuses, err = p.billingStatusChanges(token)
		if err != nil {
			return "", err
		}
	}

	// Determine the proposal status
	propStatus, err = proposalStatus(recordState, recordStatus, voteStatus,
		voteMetadata, billingStatuses)
	if err != nil {
		return "", nil
	}

	// Cache the results
	p.statuses.set(tokenStr, statusEntry{
		propStatus:   propStatus,
		recordState:  recordState,
		recordStatus: recordStatus,
		voteStatus:   voteStatus,
		voteMetadata: voteMetadata,
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

// statusRequiresVoteSummary returns whether the proposal status requires the
// vote summary to be retrieved. This is necessary when the proposal is in
// a stage where the vote status can still change.
func statusRequiresVoteSummary(s pi.PropStatusT) bool {
	if statusIsFinal(s) {
		// The status is final and cannot be changed
		// any further, which means the vote summary
		// is not required.
		return false
	}

	switch s {
	case pi.PropStatusActive, pi.PropStatusClosed, pi.PropStatusCompleted:
		// The vote result is known, no need to fetch
		return false

	case pi.PropStatusUnvetted, pi.PropStatusUnderReview,
		pi.PropStatusVoteAuthorized, pi.PropStatusVoteStarted:
		// Vote status changes are possible, we need to fetch the latest
		return true

	default:
		// Defaulting to true is the conservative default
		// since it will force the vote summary to be retrieved
		// for unhandled cases.
		return true
	}
}

// statusRequiresBillingStatuses returns whether the proposal status requires
// the billing status changes to be retrieved. This is necessary when the
// proposal is in a stage where it's billing status still can change.
func statusRequiresBillingStatuses(s pi.PropStatusT) bool {
	if statusIsFinal(s) {
		// The status is final and cannot be changed
		// any further, which means billing status
		// changes are not required.
		return false
	}

	switch s {
	case pi.PropStatusUnvetted, pi.PropStatusVoteAuthorized,
		pi.PropStatusUnderReview, pi.PropStatusVoteStarted:
		// No need to fetch billing status changes yet
		return false

	case pi.PropStatusActive, pi.PropStatusCompleted, pi.PropStatusClosed:
		// New billing status changes are still possible, we need to fetch the
		// latest.
		return true

	default:
		// Defaulting to true is the conservative default
		// since it will force the billing status changes
		// to be retrieved for unhandled cases.
		return true
	}
}
