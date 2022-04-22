// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// proposal contains the full contents of a tstore proposal.
type proposal struct {
	RecordMetadata backend.RecordMetadata

	// Files includes the proposal index file and image attachments.
	Files []backend.File

	// The following fields are converted into backend files before being
	// imported into tstore.
	//
	// The VoteMetadata will only exist for RFPs and RFP submissions.
	ProposalMetadata pi.ProposalMetadata
	VoteMetadata     *ticketvote.VoteMetadata

	// The following fields are converted into backend metadata streams before
	// being imported into tstore.
	//
	// A public proposal will only have one status change returned. The status
	// change of when the proposal was made public.
	//
	// An abandoned proposal will have two status changes returned. The status
	// change from when the proposal was made public and the status change from
	// when the proposal was marked as abandoned.
	//
	// All other status changes are not public data and thus will not have been
	// included in the legacy git repo.
	UserMetadata  usermd.UserMetadata
	StatusChanges []usermd.StatusChangeMetadata

	// comments plugin data. These fields may be nil depeneding on the proposal.
	//
	// These fields are imported into tstore as plugin data blobs.
	CommentAdds  []comments.CommentAdd
	CommentDels  []comments.CommentDel
	CommentVotes []comments.CommentVote

	// ticketvote plugin data. These fields may be nil depending on the proposal,
	// i.e. abandoned proposals will not have ticketvote data.
	//
	// These fields are imported into tstore as plugin data blobs.
	AuthDetails *ticketvote.AuthDetails
	VoteDetails *ticketvote.VoteDetails
	CastVotes   []ticketvote.CastVoteDetails
}

// isRFP returns whether the proposal is an RFP. RFPs will have
// their VoteMetadata LinkBy field set.
func (p *proposal) isRFP() bool {
	return p.VoteMetadata != nil && p.VoteMetadata.LinkBy > 0
}

// isRFPSubmission returns whether the proposal is an RFP submission. RFP
// submissions will have their VoteMetadata LinkTo field set.
func (p *proposal) isRFPSubmission() bool {
	return p.VoteMetadata != nil && p.VoteMetadata.LinkTo != ""
}

// writeProposal writes a proposal to disk.
func writeProposal(legacyDir string, p proposal) error {
	fp := proposalPath(legacyDir, p.ProposalMetadata.LegacyToken)
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fp, b, filePermissions)
}

// readProposal reads a proposal from disk.
func readProposal(legacyDir, legacyToken string) (*proposal, error) {
	fp := proposalPath(legacyDir, legacyToken)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	var p proposal
	err = json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// proposalExists returns whether the proposal exists on disk.
func proposalExists(legacyDir, legacyToken string) (bool, error) {
	fp := proposalPath(legacyDir, legacyToken)
	if _, err := os.Stat(fp); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// proposalPath returns the file path for a proposal in the legacy directory.
func proposalPath(legacyDir, legacyToken string) string {
	return filepath.Join(legacyDir, legacyToken+".json")
}

// verifyProposal performs basic sanity checks on the converted proposal data.
// These checks should be run prior to
func verifyProposal(p proposal) error {
	// Verify that required data is present. Plugin
	// data like comment and ticketvote plugin data
	// will not be present on all proposal so is not
	// checked.
	switch {
	case p.RecordMetadata.Token == "":
		return fmt.Errorf("record metadata not found")
	case len(p.Files) == 0:
		return fmt.Errorf("no files found")
	case p.ProposalMetadata.Name == "":
		return fmt.Errorf("proposal metadata not found")
	case p.UserMetadata.UserID == "":
		return fmt.Errorf("user metadata not found")
	case len(p.StatusChanges) == 0:
		return fmt.Errorf("status changes not found")
	}

	// Perform checks that are dependent on the record status
	switch p.RecordMetadata.Status {
	case backend.StatusArchived:
		// Archived proposals will have two status changes
		// and no vote data.
		if len(p.StatusChanges) != 2 {
			return fmt.Errorf("invalid status changes count")
		}
		if p.StatusChanges[0].Status != uint32(backend.StatusPublic) {
			return fmt.Errorf("invalid status change")
		}
		if p.StatusChanges[1].Status != uint32(backend.StatusArchived) {
			return fmt.Errorf("invalid status change")
		}
		if p.AuthDetails != nil {
			return fmt.Errorf("auth details invalid")
		}
		if p.VoteDetails != nil {
			return fmt.Errorf("vote details invalid")
		}
		if len(p.CastVotes) != 0 {
			return fmt.Errorf("cast votes invalid")
		}

	case backend.StatusPublic:
		// All non-archived proposals will be public, with a
		// single status change, and will have the vote data
		// populated.
		if len(p.StatusChanges) != 1 {
			return fmt.Errorf("invalid status changes count")
		}
		if p.StatusChanges[0].Status != uint32(backend.StatusPublic) {
			return fmt.Errorf("invalid status change")
		}
		if p.AuthDetails == nil {
			return fmt.Errorf("auth details missing")
		}
		if p.VoteDetails == nil {
			return fmt.Errorf("vote details missing")
		}
		if len(p.CastVotes) == 0 {
			return fmt.Errorf("cast votes missing")
		}

	default:
		return fmt.Errorf("unknown record status")
	}

	return nil
}

/*
TODO
Remove broken signatures

Signatures that are broken:
- usermd StatusChangeMetadata signature (wrong message)
- ticketvote AuthDetails receipt (wrong server pubkey)
- ticketvote VoteDetails signature (wrong message)
- ticketvote VoteDetails receipt (wrong message, wrong server pubkey)

Fields that have been updated:
- RecordMetadata
	-[x] Version and iteration are updated to 1
- ProposalMetadata
  -[x] LegacyToken is populated
- VoteMetadata
  -[ ] LinkTo is updated with the tstore legacy RFP submissions
*/

// overwriteProposalFields overwrites legacy proposal fields that are required
// to be changed or removed in order to be successfully imported into the
// tstore backend.
//
// Documentation for each field that is updated is provided below and details
// the specific reason for the update.
func overwriteProposalFields(p *proposal, tstoreToken []byte) error {
	// The record metadata version and iteration must both
	// be update to be 1. This is required because the tstore
	// backend expects the versions and iterations to be
	// sequential. For example, the tstore backend will error
	// if it finds a record that contains a iteration 2, but
	// not iteration 1. We only import the most recent
	// version and iteration of a legacy proposal, so we must
	// update the record metadata to reflect that.
	p.RecordMetadata.Version = 1
	p.RecordMetadata.Iteration = 1

	// The legacy git backend token must be added to the
	// ProposalMetadata. All legacy proposal will have this
	// field populated. It allows clients to know that this
	// is a legacy git backend proposal and to treat it
	// accordingly.
	p.ProposalMetadata.LegacyToken = p.RecordMetadata.Token

	return nil
}
