// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package comments provides a plugin for extending a record with comment
// functionality.
package comments

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "comments"

	// Plugin commands
	CmdNew        = "new"        // Create a new comment
	CmdEdit       = "edit"       // Edit a comment
	CmdDel        = "del"        // Del a comment
	CmdVote       = "vote"       // Vote on a comment
	CmdGet        = "get"        // Get specified comments
	CmdGetAll     = "getall"     // Get all comments for a record
	CmdGetVersion = "getversion" // Get specified version of a comment
	CmdCount      = "count"      // Get comments count for a record
	CmdVotes      = "votes"      // Get comment votes
	CmdTimestamps = "timestamps" // Get timestamps
)

// Plugin setting keys can be used to specify custom plugin settings. Default
// plugin setting values can be overridden by providing a plugin setting key
// and value to the plugin on startup.
const (
	// SettingKeyCommentLengthMax is the plugin setting key for the
	// SettingCommentLengthMax plugin setting.
	SettingKeyCommentLengthMax = "commentlengthmax"

	// SettingKeyVoteChangesMax is the plugin setting key for the
	// SettingVoteChangesMax plugin setting.
	SettingKeyVoteChangesMax = "votechangesmax"

	// SettingKeyAllowExtraData is the plugin setting key for the
	// SettingAllowExtraData plugin setting.
	SettingKeyAllowExtraData = "allowextradata"
)

// Plugin setting default values. These can be overridden by providing a plugin
// setting key and value to the plugin on startup.
const (
	// SettingCommentLengthMax is the default maximum number of
	// characters that are allowed in a comment.
	SettingCommentLengthMax uint32 = 8000

	// SettingVoteChangesMax is the default maximum number of times a
	// user can change their vote on a comment. This prevents a
	// malicious user from being able to spam comment votes.
	SettingVoteChangesMax uint32 = 5

	// SettingAllowExtraData is the default value of the bool flag which
	// determines whether posting extra data along with the comment is allowed.
	SettingAllowExtraData = false
)

// ErrorCodeT represents a error that was caused by the user.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeTokenInvalid is returned when a token is invalid.
	ErrorCodeTokenInvalid ErrorCodeT = 1

	// ErrorCodePublicKeyInvalid is returned when a public key is
	// invalid.
	ErrorCodePublicKeyInvalid ErrorCodeT = 2

	// ErrorCodeSignatureInvalid is returned when a signature is
	// invalid.
	ErrorCodeSignatureInvalid ErrorCodeT = 3

	// ErrorCodeMaxLengthExceeded is returned when a comment exceeds the
	// max length plugin setting.
	ErrorCodeMaxLengthExceeded ErrorCodeT = 4

	// ErrorCodeNoChanges is returned when a comment edit does not
	// contain any changes.
	ErrorCodeNoChanges ErrorCodeT = 5

	// ErrorCodeCommentNotFound is returned when a comment could not be
	// found.
	ErrorCodeCommentNotFound ErrorCodeT = 6

	// ErrorCodeUserUnauthorized is returned when a user is attempting
	// to edit a comment that they did not submit.
	ErrorCodeUserUnauthorized ErrorCodeT = 7

	// ErrorCodeParentIDInvalid is returned when a comment parent ID
	// does not correspond to an actual comment.
	ErrorCodeParentIDInvalid ErrorCodeT = 8

	// ErrorCodeVoteInvalid is returned when a comment vote is invalid.
	ErrorCodeVoteInvalid ErrorCodeT = 9

	// ErrorCodeVoteChangesMaxExceeded is returned when the number of
	// times the user has changed their vote has exceeded the vote
	// changes max plugin setting.
	ErrorCodeVoteChangesMaxExceeded ErrorCodeT = 10

	// ErrorCodeRecordStateInvalid is returned when the provided state
	// does not match the record state.
	ErrorCodeRecordStateInvalid ErrorCodeT = 11

	// ErrorCodeExtraDataNotAllowed is returned when comment extra data
	// is found while comment plugin setting does not allow it.
	ErrorCodeExtraDataNotAllowed = 12

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 13
)

var (
	// ErrorCodes contains the human readable error messages.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                "error code invalid",
		ErrorCodeTokenInvalid:           "token invalid",
		ErrorCodePublicKeyInvalid:       "public key invalid",
		ErrorCodeSignatureInvalid:       "signature invalid",
		ErrorCodeMaxLengthExceeded:      "max length exceeded",
		ErrorCodeNoChanges:              "no changes",
		ErrorCodeCommentNotFound:        "comment not found",
		ErrorCodeUserUnauthorized:       "user unauthorized",
		ErrorCodeParentIDInvalid:        "parent id invalid",
		ErrorCodeVoteInvalid:            "vote invalid",
		ErrorCodeVoteChangesMaxExceeded: "vote changes max exceeded",
		ErrorCodeRecordStateInvalid:     "record state invalid",
		ErrorCodeExtraDataNotAllowed:    "comment extra data not allowed",
	}
)

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
// If a comment is deleted the PublicKey, Signature, Receipt, and Timestamp
// fields will be the from the deletion action, not from the original comment.
// The only field that is retained from the original comment is the UserID
// field so that the client can still display the correct user information for
// the deleted comment. Everything else from the original comment is
// permanently deleted.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + ParentID + Comment + ExtraData + ExtraDataHint
//
// Receipt is the server signature of the user signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type Comment struct {
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	ParentID  uint32       `json:"parentid"`  // Parent comment ID if reply
	Comment   string       `json:"comment"`   // Comment text
	PublicKey string       `json:"publickey"` // Public key used for Signature
	Signature string       `json:"signature"` // Client signature
	CommentID uint32       `json:"commentid"` // Comment ID
	Version   uint32       `json:"version"`   // Comment version
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

// CommentAdd is the structure that is saved to disk when a comment is created
// or edited.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + ParentID + Comment + ExtraData + ExtraDataHint
//
// Receipt is the server signature of the user signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type CommentAdd struct {
	// Data generated by client
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	ParentID  uint32       `json:"parentid"`  // Parent comment ID
	Comment   string       `json:"comment"`   // Comment
	PublicKey string       `json:"publickey"` // Pubkey used for Signature
	Signature string       `json:"signature"` // Client signature

	// Metadata generated by server
	CommentID uint32 `json:"commentid"` // Comment ID
	Version   uint32 `json:"version"`   // Comment version
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// CommentDel is the structure that is saved to disk when a comment is deleted.
// Some additional fields like ParentID and UserID are required to be saved
// since all the CommentAdd records will be deleted and the client needs these
// additional fields to properly display the deleted comment in the comment
// hierarchy.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + CommentID + Reason
//
// The PublicKey and Signature are hex encoded and use the
// ed25519 signature scheme.
type CommentDel struct {
	// Data generated by client
	Token     string       `json:"token"`     // Record token
	State     RecordStateT `json:"state"`     // Record state
	CommentID uint32       `json:"commentid"` // Comment ID
	Reason    string       `json:"reason"`    // Reason for deleting
	PublicKey string       `json:"publickey"` // Pubkey used for Signature
	Signature string       `json:"signature"` // Client signature

	// Metadata generated by server
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	UserID    string `json:"userid"`    // Author user ID
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server sig of client sig
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

// CommentVote is the structure that is saved to disk when a comment is voted
// on.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + CommentID + Vote
//
// The PublicKey and Signature are hex encoded and use the
// ed25519 signature scheme.
type CommentVote struct {
	// Data generated by client
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	CommentID uint32       `json:"commentid"` // Comment ID
	Vote      VoteT        `json:"vote"`      // Upvote or downvote
	PublicKey string       `json:"publickey"` // Public key used for signature
	Signature string       `json:"signature"` // Client signature

	// Metadata generated by server
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// New creates a new comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + ParentID + Comment + ExtraData + ExtraDataHint
//
// Receipt is the server signature of the user signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type New struct {
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	ParentID  uint32       `json:"parentid"`  // Parent comment ID
	Comment   string       `json:"comment"`   // Comment text
	PublicKey string       `json:"publickey"` // Pubkey used for Signature
	Signature string       `json:"signature"` // Client signature

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// NewReply is the reply to the New command.
type NewReply struct {
	Comment Comment `json:"comment"`
}

// Edit edits an existing comment.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + ParentID + Comment + ExtraData + ExtraDataHint
//
// Receipt is the server signature of the user signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type Edit struct {
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	ParentID  uint32       `json:"parentid"`  // Parent comment ID
	CommentID uint32       `json:"commentid"` // Comment ID
	Comment   string       `json:"comment"`   // Comment text
	PublicKey string       `json:"publickey"` // Pubkey used for Signature
	Signature string       `json:"signature"` // Client signature

	// Optional fields to be used freely
	ExtraData     string `json:"extradata,omitempty"`
	ExtraDataHint string `json:"extradatahint,omitempty"`
}

// EditReply is the reply to the Edit command.
type EditReply struct {
	Comment Comment `json:"comment"`
}

// Del permanently deletes all versions of the provided comment.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + CommentID + Reason
//
// The PublicKey and Signature are hex encoded and use the
// ed25519 signature scheme.
type Del struct {
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	CommentID uint32       `json:"commentid"` // Comment ID
	Reason    string       `json:"reason"`    // Reason for deletion
	PublicKey string       `json:"publickey"` // Public key used for signature
	Signature string       `json:"signature"` // Client signature
}

// DelReply is the reply to the Del command.
type DelReply struct {
	Comment Comment `json:"comment"`
}

// Vote casts a comment vote (upvote or downvote).
//
// The effect of a new vote on a comment score depends on the previous vote
// from that user ID. Example, a user upvotes a comment that they have already
// upvoted, the resulting vote score is 0 due to the second upvote removing the
// original upvote. The public key cannot be relied on to remain the same for
// each user so a user ID must be included.
//
// PublicKey is the user's public key that is used to verify the signature.
//
// Signature is the user signature of the:
// State + Token + CommentID + Vote
//
// The PublicKey and Signature are hex encoded and use the
// ed25519 signature scheme.
type Vote struct {
	UserID    string       `json:"userid"`    // Unique user ID
	State     RecordStateT `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	CommentID uint32       `json:"commentid"` // Comment ID
	Vote      VoteT        `json:"vote"`      // Upvote or downvote
	PublicKey string       `json:"publickey"` // Public key used for signature
	Signature string       `json:"signature"` // Client signature
}

// VoteReply is the reply to the Vote command.
type VoteReply struct {
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// Get retrieves a batch of specified comments. The most recent version of each
// comment is returned. An error is not returned if a comment is not found for
// one or more of the comment IDs. Those entries will simply not be included in
// the reply.
type Get struct {
	CommentIDs []uint32 `json:"commentids"`
}

// GetReply is the reply to the Get command. The returned map will not include
// an entry for any comment IDs that did not correspond to an actual comment.
// It is the responsibility of the caller to ensure that a comment was returned
// for all of the provided comment IDs.
type GetReply struct {
	Comments map[uint32]Comment `json:"comments"` // [commentID]Comment
}

// GetAll retrieves all comments for a record. The latest version of each
// comment is returned.
type GetAll struct{}

// GetAllReply is the reply to the GetAll command. The returned comments array
// is ordered by comment ID from smallest to largest.
type GetAllReply struct {
	Comments []Comment `json:"comments"`
}

// GetVersion retrieves the specified version of a comment.
type GetVersion struct {
	CommentID uint32 `json:"commentid"`
	Version   uint32 `json:"version"`
}

// GetVersionReply is the reply to the GetVersion command.
type GetVersionReply struct {
	Comment Comment `json:"comment"`
}

// Count retrieves the comments count for a record. The comments count is the
// number of comments that have been made on a record.
type Count struct{}

// CountReply is the reply to the Count command.
type CountReply struct {
	Count uint32 `json:"count"`
}

// Votes retrieves the comment votes that meet the provided filtering criteria.
type Votes struct {
	UserID string `json:"userid"`
}

// VotesReply is the reply to the Votes command.
type VotesReply struct {
	Votes []CommentVote `json:"votes"`
}

// Proof contains an inclusion proof for the digest in the merkle root. The
// ExtraData field is used by certain types of proofs to include additional
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

// CommentTimestamp contains the timestamps for the full history of a single
// comment.
//
// A CommentAdd is the structure that is saved to disk anytime a comment is
// created or edited. This structure is what will be timestamped.  The data
// payload of a timestamp in the Adds field will contain a JSON encoded
// CommentAdd.
//
// A CommentDel is the structure that is saved to disk anytime a comment is
// deleted. This structure is what will be timestamped. The data payload of a
// timestamp in the Del field will contain a JSON encoded CommentDel.
//
// A CommentVote is the structure that is saved to disk anytime a comment is
// voted on. This structure is what will be timestamped. The data payload of
// a timestamp in the Votes filed will contain a JSON encoded CommentVote.
type CommentTimestamp struct {
	Adds  []Timestamp `json:"adds"`
	Del   *Timestamp  `json:"del,omitempty"`
	Votes []Timestamp `json:"votes,omitempty"`
}

// Timestamps retrieves the timestamps for a record's comments. If a requested
// comment ID does not exist, it will not be included in the reply. An error is
// not returned.
//
// If IncludeVotes is set to true then the timestamps for the comment votes
// will also be returned.
type Timestamps struct {
	CommentIDs   []uint32 `json:"commentids"`
	IncludeVotes bool     `json:"includevotes,omitempty"`
}

// TimestampsReply is the reply to the timestamps command.
type TimestampsReply struct {
	Comments map[uint32]CommentTimestamp `json:"comments"`
}
