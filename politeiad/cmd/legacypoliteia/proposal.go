// Copyright (c) 2021 The Decred developers
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
	Files          []backend.File
	Metadata       []backend.MetadataStream

	// pi plugin
	ProposalMetadata pi.ProposalMetadata

	// usermd plugin
	StatusChanges []usermd.StatusChangeMetadata

	// ticketvote plugin
	VoteMetadata ticketvote.VoteMetadata
	AuthDetails  ticketvote.AuthDetails
	VoteDetails  ticketvote.VoteDetails
	CastVotes    []ticketvote.CastVoteDetails

	// comments plugin
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

// loadProposal loads a proposal from disk.
func loadProposal(legacyDir, gitToken string) (*proposal, error) {
	fp := proposalPath(legacyDir, gitToken)
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

// proposalPath returns the file path for a proposal in the legacy directory.
func proposalPath(legacyDir, gitToken string) string {
	return filepath.Join(legacyDir, gitToken+".json")
}

// voteCollider is an internal ticketvote plugin type that is not exported, so
// it's duplicated here.
type voteCollider struct {
	Token  string `json:"token"`
	Ticket string `json:"ticket"`
}

// startRunoffRecord is an internal ticketvote plugin type that is not
// exported, so it's duplicated here.
type startRunoffRecord struct {
	Submissions      []string `json:"submissions"`
	Mask             uint64   `json:"mask"`
	Duration         uint32   `json:"duration"`
	QuorumPercentage uint32   `json:"quorumpercentage"`
	PassPercentage   uint32   `json:"passpercentage"`
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}
