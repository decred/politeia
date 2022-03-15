// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io/ioutil"
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
	// This is an optional pointer as unvetted propsoals shouldn't have any
	// status changes.
	StatusChange *usermd.StatusChangeMetadata

	// ticketvote plugin data. These fields may be nil depending on the proposal,
	// i.e. abandoned proposals will not have ticketvote data.
	AuthDetails *ticketvote.AuthDetails
	VoteDetails *ticketvote.VoteDetails
	CastVotes   []ticketvote.CastVoteDetails

	// comments plugin data. These fields may be nil depeneding on the proposal.
	CommentAdds  []comments.CommentAdd
	CommentDels  []comments.CommentDel
	CommentVotes []comments.CommentVote
}

// saveProposal saves the provided proposal to disk.
func saveProposal(legacyDir string, p *proposal) error {
	fp := proposalPath(legacyDir, p.ProposalMetadata.LegacyToken)
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fp, b, filePermissions)
}

// proposalPath returns the file path for a proposal in the legacy directory.
func proposalPath(legacyDir, gitToken string) string {
	return filepath.Join(legacyDir, gitToken+".json")
}
