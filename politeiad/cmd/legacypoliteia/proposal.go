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
	UserMetadata usermd.UserMetadata
	StatusChange usermd.StatusChangeMetadata

	// comments plugin data. These fields may be nil depeneding on the proposal.
	CommentAdds  []comments.CommentAdd
	CommentDels  []comments.CommentDel
	CommentVotes []comments.CommentVote

	// ticketvote plugin data. These fields may be nil depending on the proposal,
	// i.e. abandoned proposals will not have ticketvote data.
	AuthDetails *ticketvote.AuthDetails
	VoteDetails *ticketvote.VoteDetails
	CastVotes   []ticketvote.CastVoteDetails
}

// verify performs basic sanity checks on the proposal data.
func (p *proposal) verify() error {
	switch {
	case p.RecordMetadata.Token == "":
		return fmt.Errorf("record metadata not found")
	case len(p.Files) == 0:
		return fmt.Errorf("no files found")
	case p.ProposalMetadata.Name == "":
		return fmt.Errorf("missing proposal name")
	case p.ProposalMetadata.LegacyToken == "":
		return fmt.Errorf("missing legacy token")
	case p.UserMetadata.UserID == "":
		return fmt.Errorf("missing user id")
	case p.UserMetadata.PublicKey == "":
		return fmt.Errorf("missing record public key")
	case p.UserMetadata.Signature == "":
		return fmt.Errorf("missing record signature")
	case p.StatusChange.Status == 0:
		return fmt.Errorf("missing status change")
	}

	// Checks based on record status
	switch p.RecordMetadata.Status {
	case backend.StatusArchived:
		// Archived proposals will have two status changes and
		// no vote data. Only the most recent status change is
		// converted.
		if p.StatusChange.Status != uint32(backend.StatusArchived) {
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
		if p.StatusChange.Status != uint32(backend.StatusPublic) {
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
