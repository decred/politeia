// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

const (
	// Journal filenames
	CommentsJournalFilename = "comments.journal"
	BallotJournalFilename   = "ballot.journal"

	// Journal actions
	JournalActionAdd     = "add"     // Add entry
	JournalActionDel     = "del"     // Delete entry
	JournalActionAddLike = "addlike" // Add comment like
)

// JournalAction prefixes and determines what the next structure is in
// the JSON journal.
//
// Version is used to determine what version of the comment journal structure
// follows.
//
// journalActionAdd -> Add entry
// journalActionDel -> Delete entry
// journalActionAddLike -> Add comment like structure (comments only)
type JournalAction struct {
	Version string `json:"version"` // Version
	Action  string `json:"action"`  // Add/Del
}

// LikeComment records an up or down vote from a user on a comment.
//
// Signature is the client signature of the Token+CommentID+Action.
type LikeComment struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Action    string `json:"action"`    // Up or downvote (1, -1)
	Signature string `json:"signature"` // Client signature
	PublicKey string `json:"publickey"` // Client public key

	// Only used on disk
	Receipt   string `json:"receipt,omitempty"`   // Server receipt
	Timestamp int64  `json:"timestamp,omitempty"` // Received UNIX timestamp
}

// CastVoteJournal represents a ballot journal entry.
type CastVoteJournal struct {
	CastVote CastVote `json:"castvote"`
	Receipt  string   `json:"receipt"` // Server receipt
}

// CastVote is a signed vote.
//
// Signature is the signature of the Token+Ticket+VoteBit.
type CastVote struct {
	Token     string `json:"token"`
	Ticket    string `json:"ticket"`
	VoteBit   string `json:"votebit"`
	Signature string `json:"signature"`
}
