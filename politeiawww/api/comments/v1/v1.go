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
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

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
	ErrorCodePageSizeExceeded   ErrorCodeT = 9
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
		ErrorCodePageSizeExceeded:   "page size exceeded",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e PluginErrorReply) Error() string {
	return fmt.Sprintf("plugin %v error code: %v", e.PluginID, e.ErrorCode)
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

// RecordStateT represents the state of a record.
type RecordStateT uint32

const (
	// RecordStateInvalid is an invalid record state.
	RecordStateInvalid RecordStateT = 0

	// RecordStateUnvetted indicates a record has not been made public.
	RecordStateUnvetted RecordStateT = 1

	// RecordStateVetted indicates a record has been made public.
	RecordStateVetted RecordStateT = 2
)

// Comment represent a record comment.
//
// A parent ID of 0 indicates that the comment is a base level comment and not
// a reply commment.
//
// Comments made on a record when it is unvetted and when it is vetted are
// treated as two distinct groups of comments. When a record becomes vetted the
// comment ID starts back at 1.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type Comment struct {
	UserID    string       `json:"userid"`    // Unique user ID
	Username  string       `json:"username"`  // Username
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	ParentID  uint32       `json:"parentid"`  // Parent comment ID if reply
	Comment   string       `json:"comment"`   // Comment text
	PublicKey string       `json:"publickey"` // Public key used for Signature
	Signature string       `json:"signature"` // Client signature
	CommentID uint32       `json:"commentid"` // Comment ID
	Timestamp int64        `json:"timestamp"` // UNIX timestamp of last edit
	Receipt   string       `json:"receipt"`   // Server sig of client sig
	Downvotes uint64       `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64       `json:"upvotes"`   // Total upvotes on comment

	Deleted bool   `json:"deleted,omitempty"` // Comment has been deleted
	Reason  string `json:"reason,omitempty"`  // Reason for deletion

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// CommentVote represents a comment vote (upvote/downvote).
//
// Signature is the client signature of the State+Token+CommentID+Vote.
type CommentVote struct {
	UserID    string       `json:"userid"`    // Unique user ID
	Username  string       `json:"username"`  // Username
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	CommentID uint32       `json:"commentid"` // Comment ID
	Vote      VoteT        `json:"vote"`      // Upvote or downvote
	PublicKey string       `json:"publickey"` // Public key used for signature
	Signature string       `json:"signature"` // Client signature
	Timestamp int64        `json:"timestamp"` // Received UNIX timestamp
	Receipt   string       `json:"receipt"`   // Server sig of client sig
}

// New creates a new comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type New struct {
	State     RecordStateT `json:"state"`
	Token     string       `json:"token"`
	ParentID  uint32       `json:"parentid"`
	Comment   string       `json:"comment"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// NewReply is the reply to the New command.
type NewReply struct {
	Comment Comment `json:"comment"`
}

// VoteT represents a comment upvote/downvote.
type VoteT int32

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
// Signature is the client signature of the State+Token+CommentID+Vote.
type Vote struct {
	State     RecordStateT `json:"state"`
	Token     string       `json:"token"`
	CommentID uint32       `json:"commentid"`
	Vote      VoteT        `json:"vote"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`
}

// VoteReply is the reply to the Vote command.
type VoteReply struct {
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server sig of client sig
}

// Del permanently deletes the provided comment. Only admins can delete
// comments. A reason must be given for the deletion.
//
// Signature is the client signature of the State+Token+CommentID+Reason
type Del struct {
	State     RecordStateT `json:"state"`
	Token     string       `json:"token"`
	CommentID uint32       `json:"commentid"`
	Reason    string       `json:"reason"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`
}

// DelReply is the reply to the Del command.
type DelReply struct {
	Comment Comment `json:"comment"`
}

const (
	// CountPageSize is the maximum number of tokens that can be
	// included in the Count command.
	CountPageSize uint32 = 10
)

// Count requests the number of comments on that have been made on the given
// records. If a record is not found for a token then it will not be included
// in the returned map.
type Count struct {
	Tokens []string `json:"tokens"`
}

// CountReply is the reply to the count command.
type CountReply struct {
	Counts map[string]uint32 `json:"counts"`
}

// Comments requests a record's comments.
type Comments struct {
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

const (
	// TimestampsPageSize is the maximum number of comment timestamps
	// that can be requests at any one time.
	TimestampsPageSize uint32 = 100
)

// CommentTimestamp contains the timestamps for the full history of a single
// comment.
//
// A CommentAdd is the comments plugin structure that is saved to disk anytime
// a comment is created or edited. This structure is what will be timestamped.
// The data payload of a timestamp in the Adds field will contain a JSON
// encoded CommentAdd. See the politeiad comments plugin API for more details
// on a CommentAdd.
//
// A CommentDel is the comments plugin structure that is saved to disk anytime
// a comment is deleted. This structure is what will be timestamped. The data
// payload of a timestamp in the Del field will contain a JSON encoded
// CommentDel. See the politeiad comments plugin API for more details on a
// CommentDel.
type CommentTimestamp struct {
	Adds []Timestamp `json:"adds"`
	Del  *Timestamp  `json:"del,omitempty"`
}

// Timestamps requests the timestamps for the comments of a record.
type Timestamps struct {
	Token      string   `json:"token"`
	CommentIDs []uint32 `json:"commentids"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	// map[commentID]CommentTimestamp
	Comments map[uint32]CommentTimestamp `json:"comments"`
}
