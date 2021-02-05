// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/comments/v1"

	// Routes
	RoutePolicy     = "/policy"
	RouteNew        = "/new"
	RouteVote       = "/vote"
	RouteDel        = "/del"
	RouteCount      = "/count"
	RouteComments   = "/comments"
	RouteVotes      = "/votes"
	RouteTimestamps = "/timestamps"

	// Record states
	RecordStateUnvetted = "unvetted"
	RecordStateVetted   = "vetted"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT int

const (
	ErrorCodeInvalid            ErrorCodeT = 0
	ErrorCodeInputInvalid       ErrorCodeT = 1
	ErrorCodeUnauthorized       ErrorCodeT = 2
	ErrorCodePublicKeyInvalid   ErrorCodeT = 3
	ErrorCodeSignatureInvalid   ErrorCodeT = 4
	ErrorCodeRecordStateInvalid ErrorCodeT = 5
	ErrorCodeTokenInvalid       ErrorCodeT = 6
	ErrorCodeRecordNotFound     ErrorCodeT = 7
	ErrorCodeRecordLocked       ErrorCodeT = 8
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:            "error invalid",
		ErrorCodeInputInvalid:       "input invalid",
		ErrorCodeUnauthorized:       "unauthorized",
		ErrorCodePublicKeyInvalid:   "public key invalid",
		ErrorCodeSignatureInvalid:   "signature invalid",
		ErrorCodeRecordStateInvalid: "record state invalid",
		ErrorCodeTokenInvalid:       "token invalid",
		ErrorCodeRecordNotFound:     "record not found",
		ErrorCodeRecordLocked:       "record is locked",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    int    `json:"errorcode"`
	ErrorContext string `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e PluginErrorReply) Error() string {
	return fmt.Sprintf("plugin error code: %v", e.ErrorCode)
}

// ServerErrorReply is the reply that the server returns when it encounters an
// unrecoverable error while executing a command. The HTTP status code will be
// 500 and the ErrorCode field will contain a UNIX timestamp that the user can
// provide to the server admin to track down the error details in the logs.
type ServerErrorReply struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e ServerErrorReply) Error() string {
	return fmt.Sprintf("server error: %v", e.ErrorCode)
}

// Policy requests the comments API policy.
type Policy struct{}

// PolicyReply is the reply to the policy command.
type PolicyReply struct {
	LengthMax      uint32 `json:"lengthmax"` // In characters
	VoteChangesMax uint32 `json:"votechangesmax"`
}

// Comment represent a record comment.
//
// Signature is the client signature of Token+ParentID+Comment.
type Comment struct {
	UserID    string `json:"userid"`    // Unique user ID
	Username  string `json:"username"`  // Username
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID if reply
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Public key used for Signature
	Signature string `json:"signature"` // Client signature
	CommentID uint32 `json:"commentid"` // Comment ID
	Timestamp int64  `json:"timestamp"` // UNIX timestamp of last edit
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment

	Deleted bool   `json:"deleted,omitempty"` // Comment has been deleted
	Reason  string `json:"reason,omitempty"`  // Reason for deletion

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// CommentVote represents a comment vote (upvote/downvote).
//
// Signature is the client signature of the Token+CommentID+Vote.
type CommentVote struct {
	UserID    string `json:"userid"`    // Unique user ID
	Username  string `json:"username"`  // Username
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Vote      VoteT  `json:"vote"`      // Upvote or downvote
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// New creates a new comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of Token+ParentID+Comment.
type New struct {
	State     string `json:"state"`
	Token     string `json:"token"`
	ParentID  uint32 `json:"parentid"`
	Comment   string `json:"comment"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// NewReply is the reply to the New command.
type NewReply struct {
	Comment Comment `json:"comment"`
}

// VoteT represents a comment upvote/downvote.
type VoteT int

const (
	// VoteInvalid is an invalid comment vote.
	VoteInvalid VoteT = 0

	// VoteDownvote represents a comment downvote.
	VoteDownvote VoteT = -1

	// VoteUpvote represents a comment upvote.
	VoteUpvote VoteT = 1
)

// Vote casts a comment vote (upvote or downvote). Votes can only be cast
// on vetted records.
//
// The effect of a new vote on a comment score depends on the previous vote
// from that user ID. Example, a user upvotes a comment that they have already
// upvoted, the resulting vote score is 0 due to the second upvote removing the
// original upvote.
//
// Signature is the client signature of the Token+CommentID+Vote.
type Vote struct {
	Token     string `json:"token"`
	CommentID uint32 `json:"commentid"`
	Vote      VoteT  `json:"vote"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

// VoteReply is the reply to the Vote command.
type VoteReply struct {
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// Del permanently deletes the provided comment. Only admins can delete
// comments. A reason must be given for the deletion.
//
// Signature is the client signature of the Token+CommentID+Reason
type Del struct {
	State     string `json:"state"`
	Token     string `json:"token"`
	CommentID uint32 `json:"commentid"`
	Reason    string `json:"reason"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

// DelReply is the reply to the Del command.
type DelReply struct {
	Comment Comment `json:"comment"`
}

// Count requests the number of comments on that have been made on the given
// records. If a record is not found for a token then it will not be included
// in the returned map.
type Count struct {
	State  string   `json:"state"`
	Tokens []string `json:"tokens"`
}

// CountReply is the reply to the count command.
type CountReply struct {
	Counts map[string]uint32 `json:"counts"`
}

// Comments requests a record's comments.
type Comments struct {
	State string `json:"state"`
	Token string `json:"token"`
}

// CommentsReply is the reply to the comments command.
type CommentsReply struct {
	Comments []Comment `json:"comments"`
}

// Votes returns the comment votes that meet the provided filtering criteria.
type Votes struct {
	Token  string `json:"token"`
	UserID string `json:"userid"`
}

// VotesReply is the reply to the Votes command.
type VotesReply struct {
	Votes []CommentVote `json:"votes"`
}

// Proof contains an inclusion proof for the digest in the merkle root. All
// digests are hex encoded SHA256 digests.
//
// The ExtraData field is used by certain types of proofs to include additional
// data that is required to validate the proof.
type Proof struct {
	Type       string   `json:"type"`
	Digest     string   `json:"digest"`
	MerkleRoot string   `json:"merkleroot"`
	MerklePath []string `json:"merklepath"`
	ExtraData  string   `json:"extradata"` // JSON encoded
}

// Timestamp contains all of the data required to verify that a piece of data
// was timestamped onto the decred blockchain.
//
// All digests are hex encoded SHA256 digests. The merkle root can be found in
// the OP_RETURN of the specified DCR transaction.
//
// TxID, MerkleRoot, and Proofs will only be populated once the merkle root has
// been included in a DCR tx and the tx has 6 confirmations. The Data field
// will not be populated if the data has been censored.
type Timestamp struct {
	Data       string  `json:"data"` // JSON encoded
	Digest     string  `json:"digest"`
	TxID       string  `json:"txid"`
	MerkleRoot string  `json:"merkleroot"`
	Proofs     []Proof `json:"proofs"`
}

// Timestamps requests the timestamps for the comments of a record. If no
// comment IDs are provided then the timestamps for all comments will be
// returned.
type Timestamps struct {
	State      string   `json:"state"`
	Token      string   `json:"token"`
	CommentIDs []uint32 `json:"commentids,omitempty"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	Comments map[uint32][]Timestamp `json:"comments"` // [commentID]Timestamp
}
