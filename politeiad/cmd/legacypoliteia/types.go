// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
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

	// LegacyToken is the git backend token for the proposal. The tstore backend
	// will use it's own, different token.
	LegacyToken string `json:"legacytoken"`
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
