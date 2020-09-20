// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
)

type ErrorStatusT int
type PropStateT int
type PropStatusT int
type CommentVoteT int
type VoteStatusT int
type VoteAuthActionT string
type VoteT int

const (
	APIVersion = 1

	// Proposal routes
	RouteProposalNew       = "/proposal/new"
	RouteProposalEdit      = "/proposal/edit"
	RouteProposalSetStatus = "/proposal/setstatus"
	RouteProposals         = "/proposals"
	RouteProposalInventory = "/proposals/inventory"

	// Comment routes
	RouteCommentNew    = "/comment/new"
	RouteCommentVote   = "/comment/vote"
	RouteCommentCensor = "/comment/censor"
	RouteComments      = "/comments"
	RouteCommentVotes  = "/comments/votes"

	// Vote routes
	RouteVoteAuthorize   = "/vote/authorize"
	RouteVoteStart       = "/vote/start"
	RouteVoteStartRunoff = "/vote/startrunoff"
	RouteVoteBallot      = "/vote/ballot"
	RouteVotes           = "/votes"
	RouteVoteResults     = "/votes/results"
	RouteVoteSummaries   = "/votes/summaries"
	RouteVoteInventory   = "/votes/inventory"

	// Proposal states. A proposal state can be either unvetted or
	// vetted. The PropStatusT type further breaks down these two
	// states into more granular statuses.
	PropStateInvalid  PropStateT = 0
	PropStateUnvetted PropStateT = 1
	PropStateVetted   PropStateT = 2

	// Proposal statuses
	PropStatusInvalid   PropStatusT = 0 // Invalid status
	PropStatusUnvetted  PropStatusT = 1 // Prop has not been vetted
	PropStatusPublic    PropStatusT = 2 // Prop has been made public
	PropStatusCensored  PropStatusT = 3 // Prop has been censored
	PropStatusAbandoned PropStatusT = 4 // Prop has been abandoned

	// Comment vote types
	CommentVoteInvalid  CommentVoteT = 0
	CommentVoteDownvote CommentVoteT = -1
	CommentVoteUpvote   CommentVoteT = 1

	// Vote statuses
	VoteStatusInvalid      VoteStatusT = 0 // Invalid status
	VoteStatusUnauthorized VoteStatusT = 1 // Vote cannot be started
	VoteStatusAuthorized   VoteStatusT = 2 // Vote can be started
	VoteStatusStarted      VoteStatusT = 3 // Vote has been started
	VoteStatusFinished     VoteStatusT = 4 // Vote has finished

	// Vote authorization actions
	VoteAuthActionAuthorize VoteAuthActionT = "authorize"
	VoteAuthActionRevoke    VoteAuthActionT = "revoke"

	// Vote types
	VoteTypeInvalid VoteT = 0

	// VoteTypeStandard is used to indicate a simple approve or reject
	// vote where the winner is the voting option that has met the
	// specified quorum and pass requirements.
	VoteTypeStandard VoteT = 1

	// VoteTypeRunoff specifies a runoff vote that multiple records
	// compete in. All records are voted on like normal, but there can
	// only be one winner in a runoff vote. The winner is the record
	// that meets the quorum requirement, meets the pass requirement,
	// and that has the most net yes votes. The winning record is
	// considered approved and all other records are considered to be
	// rejected. If no records meet the quorum and pass requirements
	// then all records are considered rejected. Note, in a runoff vote
	// it's possible for a proposal to meet both the quorum and pass
	// requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeRunoff VoteT = 2

	// Error status codes
	ErrorStatusInvalid      ErrorStatusT = 0
	ErrorStatusInvalidInput ErrorStatusT = 1

	// User errors
	ErrorStatusUserRegistrationNotPaid ErrorStatusT = 2
	ErrorStatusUserBalanceInsufficient ErrorStatusT = 3
	ErrorStatusUserIsNotAuthor         ErrorStatusT = 4
	ErrorStatusUserIsNotAdmin          ErrorStatusT = 5

	// Signature errors
	ErrorStatusPublicKeyInvalid ErrorStatusT = 100
	ErrorStatusSignatureInvalid ErrorStatusT = 101

	// Proposal errors
	ErrorStatusFileCountInvalid              ErrorStatusT = 202
	ErrorStatusFileNameInvalid               ErrorStatusT = 203
	ErrorStatusFileMIMEInvalid               ErrorStatusT = 204
	ErrorStatusFileDigestInvalid             ErrorStatusT = 205
	ErrorStatusFilePayloadInvalid            ErrorStatusT = 206
	ErrorStatusIndexFileNameInvalid          ErrorStatusT = 207
	ErrorStatusIndexFileCountInvalid         ErrorStatusT = 207
	ErrorStatusIndexFileSizeInvalid          ErrorStatusT = 208
	ErrorStatusTextFileCountInvalid          ErrorStatusT = 209
	ErrorStatusImageFileCountInvalid         ErrorStatusT = 210
	ErrorStatusImageFileSizeInvalid          ErrorStatusT = 211
	ErrorStatusMetadataCountInvalid          ErrorStatusT = 212
	ErrorStatusMetadataHintInvalid           ErrorStatusT = 213
	ErrorStatusMetadataDigestInvalid         ErrorStatusT = 214
	ErrorStatusMetadataPayloadInvalid        ErrorStatusT = 215
	ErrorStatusPropNameInvalid               ErrorStatusT = 216
	ErrorStatusPropLinkToInvalid             ErrorStatusT = 217
	ErrorStatusPropLinkByInvalid             ErrorStatusT = 218
	ErrorStatusPropTokenInvalid              ErrorStatusT = 219
	ErrorStatusPropNotFound                  ErrorStatusT = 220
	ErrorStatusPropStateInvalid              ErrorStatusT = 221
	ErrorStatusPropStatusInvalid             ErrorStatusT = 222
	ErrorStatusPropStatusChangeInvalid       ErrorStatusT = 223
	ErrorStatusPropStatusChangeReasonInvalid ErrorStatusT = 224

	// Comment errors
	// TODO number error codes
	ErrorStatusCommentTextInvalid ErrorStatusT = iota
	ErrorStatusCommentParentIDInvalid
	ErrorStatusCommentVoteInvalid
	ErrorStatusCommentNotFound
	ErrorStatusCommentMaxVoteChanges

	// Vote errors
	ErrorStatusVoteStatusInvalid
	ErrorStatusVoteDetailsInvalid
	ErrorStatusBallotInvalid
)

var (
	// APIRoute is the prefix to all API routes.
	APIRoute = fmt.Sprintf("/v%v", APIVersion)

	// ErrorStatus contains human readable error messages.
	// TODO fill in error status messages
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid: "error status invalid",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
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

// File describes an individual file that is part of the proposal. The
// directory structure must be flattened.
type File struct {
	Name    string `json:"name"`    // Filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // File content, base64 encoded
}

// Metadata describes user specified proposal metadata.
type Metadata struct {
	Hint    string `json:"hint"`    // Hint that describes the payload
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // JSON metadata content, base64 encoded
}

// Metadata hints
const (
	// HintProposalMetadata is the proposal metadata hint
	HintProposalMetadata = "proposalmetadata"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission. It is attached to a proposal submission as a Metadata object.
type ProposalMetadata struct {
	Name string `json:"name"` // Proposal name

	// LinkTo specifies a public proposal token to link this proposal
	// to. Ex, an RFP submission must link to the RFP proposal.
	LinkTo string `json:"linkto,omitempty"`

	// LinkBy is a UNIX timestamp that serves as a deadline for other
	// proposals to link to this proposal. Ex, an RFP submission cannot
	// link to an RFP proposal once the RFP's LinkBy deadline is past.
	LinkBy int64 `json:"linkby,omitempty"`
}

// CensorshipRecord contains cryptographic proof that a proposal was accepted
// for review by the server. The proof is verifiable by the client.
type CensorshipRecord struct {
	// Token is a random censorship token that is generated by the
	// server. It serves as a unique identifier for the proposal.
	Token string `json:"token"`

	// Merkle is the ordered merkle root of all files and metadata in
	// in the proposal.
	Merkle string `json:"merkle"`

	// Signature is the server signature of the Merkle+Token.
	Signature string `json:"signature"`
}

// StatusChange represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	Token     string      `json:"token"`
	Version   string      `json:"version"`
	Status    PropStatusT `json:"status"`
	Reason    string      `json:"message,omitempty"`
	PublicKey string      `json:"publickey"`
	Signature string      `json:"signature"`
	Timestamp int64       `json:"timestamp"`
}

// ProposalRecord is an entire proposal and it's contents.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalRecord struct {
	Version   string         `json:"version"`   // Proposal version
	Timestamp int64          `json:"timestamp"` // Submission UNIX timestamp
	State     PropStateT     `json:"state"`     // Proposal state
	Status    PropStatusT    `json:"status"`    // Proposal status
	UserID    string         `json:"userid"`    // Author ID
	Username  string         `json:"username"`  // Author username
	PublicKey string         `json:"publickey"` // Key used in signature
	Signature string         `json:"signature"` // Signature of merkle root
	Comments  uint64         `json:"comments"`  // Number of comments
	Statuses  []StatusChange `json:"statuses"`  // Status change history
	Files     []File         `json:"files"`     // Proposal files
	Metadata  []Metadata     `json:"metadata"`  // User defined metadata

	// LinkedFrom contains a list of public proposals that have linked
	// to this proposal. A link is established when a child proposal
	// specifies this proposal using the LinkTo field of the
	// ProposalMetadata.
	LinkedFrom []string `json:"linkedfrom"`

	// CensorshipRecord contains cryptographic proof that the proposal
	// was received by the server.
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalNew submits a new proposal.
//
// Metadata must contain a ProposalMetadata object.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalNew struct {
	Files     []File     `json:"files"`     // Proposal files
	Metadata  []Metadata `json:"metadata"`  // User defined metadata
	PublicKey string     `json:"publickey"` // Key used for signature
	Signature string     `json:"signature"` // Signature of merkle root
}

// ProposalNewReply is the reply to the ProposalNew command.
type ProposalNewReply struct {
	Timestamp        int64            `json:"timestamp"`
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalEdit edits an existing proposal.
//
// Metadata must contain a ProposalMetadata object.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalEdit struct {
	Token     string     `json:"token"`     // Censorship token
	State     PropStateT `json:"state"`     // Proposal state
	Files     []File     `json:"files"`     // Proposal files
	Metadata  []Metadata `json:"metadata"`  // User defined metadata
	PublicKey string     `json:"publickey"` // Key used for signature
	Signature string     `json:"signature"` // Signature of merkle root
}

// ProposalEditReply is the reply to the ProposalEdit command.
type ProposalEditReply struct {
	Version          string           `json:"version"`
	Timestamp        int64            `json:"timestamp"`
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalSetStatus sets the status of a proposal. Some status changes require
// a reason to be included.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type ProposalSetStatus struct {
	Token     string      `json:"token"`            // Censorship token
	State     PropStateT  `json:"state"`            // Proposal state
	Version   string      `json:"version"`          // Proposal version
	Status    PropStatusT `json:"status"`           // New status
	Reason    string      `json:"reason,omitempty"` // Reason for status change
	PublicKey string      `json:"publickey"`        // Key used for signature
	Signature string      `json:"signature"`        // Client signature
}

// ProposalSetStatusReply is the reply to the ProposalSetStatus command.
type ProposalSetStatusReply struct {
	Timestamp int64 `json:"timestamp"`
}

// ProposalRequest is used to request the ProposalRecord of the provided
// proposal token and version. If the version is omitted, the most recent
// version will be returned.
type ProposalRequest struct {
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
}

// Proposals retrieves the ProposalRecord for each of the provided proposal
// requests. Unvetted proposal files are only returned to admins.
type Proposals struct {
	State        PropStateT        `json:"state"`
	Requests     []ProposalRequest `json:"requests"`
	IncludeFiles bool              `json:"includefiles,omitempty"`
}

// ProposalsReply is the reply to the Proposals command. Any tokens that did
// not correspond to a ProposalRecord will not be included in the reply.
type ProposalsReply struct {
	Proposals map[string]ProposalRecord `json:"proposals"` // [token]Proposal
}

// ProposalInventry retrieves the tokens of all proposals in the inventory,
// catagorized by proposal status and ordered by timestamp of the status change
// from newest to oldest.
type ProposalInventory struct{}

// ProposalInventoryReply is the reply to the ProposalInventory command.
type ProposalInventoryReply struct {
	Unvetted  []string `json:"unvetted,omitempty"`
	Public    []string `json:"public"`
	Censored  []string `json:"censored"`
	Abandoned []string `json:"abandoned"`
}

// Comment represent a proposal comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type Comment struct {
	UserID    string     `json:"userid"`    // User ID
	Username  string     `json:"username"`  // Username
	State     PropStateT `json:"state"`     // Proposal state
	Token     string     `json:"token"`     // Proposal token
	ParentID  uint32     `json:"parentid"`  // Parent comment ID
	Comment   string     `json:"comment"`   // Comment text
	PublicKey string     `json:"publickey"` // Public key used for Signature
	Signature string     `json:"signature"` // Client signature
	CommentID uint32     `json:"commentid"` // Comment ID
	Version   uint32     `json:"version"`   // Comment version
	Timestamp int64      `json:"timestamp"` // UNIX timestamp of last edit
	Receipt   string     `json:"receipt"`   // Server sig of client sig
	Score     int64      `json:"score"`     // Vote score
	Deleted   bool       `json:"deleted"`   // Comment has been deleted
	Reason    string     `json:"reason"`    // Reason for deletion
}

// CommentNew creates a new comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type CommentNew struct {
	State     PropStateT `json:"state"`
	Token     string     `json:"token"`
	ParentID  uint32     `json:"parentid"`
	Comment   string     `json:"comment"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// CommentNewReply is the reply to the CommentNew command.
//
// Receipt is the server signature of the client signature. This is proof that
// the server received and processed the CommentNew command.
type CommentNewReply struct {
	CommentID uint32 `json:"commentid"`
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

// CommentCensor permanently censors a comment. The comment will be deleted
// and cannot be retrieved once censored. Only admins can censor a comment.
//
// Reason contains the reason why the comment is being censored and must always
// be included.
type CommentCensor struct {
	State     PropStateT `json:"state"`
	Token     string     `json:"token"`
	CommentID uint32     `json:"commentid"`
	Reason    string     `json:"reason"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// CommentCensorReply is the reply to the CommentCensor command.
//
// Receipt is the server signature of the client signature. This is proof that
// the server received and processed the CommentCensor command.
type CommentCensorReply struct {
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

// CommentVote casts a comment vote (upvote or downvote).
//
// The effect of a new vote on a comment score depends on the previous vote
// from that uuid. Example, a user upvotes a comment that they have already
// upvoted, the resulting vote score is 0 due to the second upvote removing the
// original upvote.
//
// Signature is the client signature of the State+Token+CommentID+Vote.
type CommentVote struct {
	State     PropStateT   `json:"state"`
	Token     string       `json:"token"`
	CommentID uint32       `json:"commentid"`
	Vote      CommentVoteT `json:"vote"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`
}

// CommentVoteReply is the reply to the CommentVote command.
//
// Receipt is the server signature of the client signature. This is proof that
// the server received and processed the CommentVote command.
type CommentVoteReply struct {
	Score     int64  `json:"score"` // Overall comment vote score
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

// Comments returns all comments for a proposal.
type Comments struct {
	State PropStateT `json:"state"`
	Token string     `json:"token"`
}

// CommentsReply is the reply to the comments command.
type CommentsReply struct {
	Comments []Comment `json:"comments"`
}

// UserCommentVote represents a comment vote made by a user. This struct
// contains all the information in a CommentVote and a CommentVoteReply.
type UserCommentVote struct {
	State     PropStateT   `json:"state"`
	Token     string       `json:"token"`
	CommentID uint32       `json:"commentid"`
	Vote      CommentVoteT `json:"vote"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`
	Timestamp int64        `json:"timestamp"`
	Receipt   string       `json:"receipt"`
}

// CommentVotes returns all comment votes made a specific user on a proposal.
type CommentVotes struct {
	State  PropStateT `json:"state"`
	Token  string     `json:"token"`
	UserID string     `json:"userid"`
}

// CommentVotesReply is the reply to the CommentVotes command.
type CommentVotesReply struct {
	Votes []UserCommentVote `json:"votes"`
}

// VoteAuthorize authorizes a proposal vote or revokes a previous vote
// authorization.  All proposal votes must be authorized by the proposal author
// before an admin is able to start the voting process.
//
// Signature contains the client signature of the Token+Version+Action.
type VoteAuthorize struct {
	Token     string          `json:"token"`
	Version   uint32          `json:"version"`
	Action    VoteAuthActionT `json:"action"`
	PublicKey string          `json:"publickey"`
	Signature string          `json:"signature"`
}

// VoteAuthorizeReply is the reply to the VoteAuthorize command.
//
// Receipt is the server signature of the client signature. This is proof that
// the server received and processed the VoteAuthorize command.
type VoteAuthorizeReply struct {
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

type VoteStart struct{}
type VoteStartReply struct{}

type VoteStartRunoff struct{}
type VoteStartRunoffReply struct{}

type VoteBallot struct{}
type VoteBallotReply struct{}

type Votes struct{}
type VotesReply struct{}

type VoteResults struct{}
type VoteResultsReply struct{}

type VoteSummaries struct{}
type VoteSummariesReply struct{}

type VoteInventory struct{}
type VoteInventoryReply struct{}
