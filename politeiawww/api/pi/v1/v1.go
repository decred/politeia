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
type VoteErrorT int

// TODO I screwed up comments. A comment should contain fields for upvotes and
// downvotes instead of just a overall vote score.
// TODO the plugin policies should be returned in a route
// TODO show the difference between unvetted censored and vetted censored
// in the proposal inventory route since fetching them requires specifying
// the state.
// TODO verify that all batched request have a page size limit
// TODO make RouteVoteResults a batched route but that only currently allows
// for 1 result to be returned so that we have the option to change this is
// we want to.

const (
	APIVersion = 1

	// APIRoute is prefixed onto all routes.
	APIRoute = "/v1"

	// Proposal routes
	RouteProposalNew       = "/proposal/new"
	RouteProposalEdit      = "/proposal/edit"
	RouteProposalStatusSet = "/proposal/setstatus"
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
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusInputInvalid     ErrorStatusT = 1
	ErrorStatusPageSizeExceeded ErrorStatusT = 2

	// User errors
	ErrorStatusUserRegistrationNotPaid ErrorStatusT = 100
	ErrorStatusUserBalanceInsufficient ErrorStatusT = 101
	ErrorStatusUnauthorized            ErrorStatusT = 102

	// Signature errors
	ErrorStatusPublicKeyInvalid ErrorStatusT = 200
	ErrorStatusSignatureInvalid ErrorStatusT = 201

	// Proposal errors
	// TODO number error codes
	ErrorStatusFileCountInvalid ErrorStatusT = 300
	ErrorStatusFileNameInvalid  ErrorStatusT = iota
	ErrorStatusFileMIMEInvalid
	ErrorStatusFileDigestInvalid
	ErrorStatusFilePayloadInvalid
	ErrorStatusIndexFileNameInvalid
	ErrorStatusIndexFileCountInvalid
	ErrorStatusIndexFileSizeInvalid
	ErrorStatusTextFileCountInvalid
	ErrorStatusImageFileCountInvalid
	ErrorStatusImageFileSizeInvalid
	ErrorStatusMetadataCountInvalid
	ErrorStatusMetadataDigestInvalid
	ErrorStatusMetadataPayloadInvalid
	ErrorStatusPropNotFound
	ErrorStatusPropMetadataNotFound
	ErrorStatusPropTokenInvalid
	ErrorStatusPropVersionInvalid
	ErrorStatusPropNameInvalid
	ErrorStatusPropLinkToInvalid
	ErrorStatusPropLinkByInvalid
	ErrorStatusPropStateInvalid
	ErrorStatusPropStatusInvalid
	ErrorStatusPropStatusChangeInvalid
	ErrorStatusPropStatusChangeReasonInvalid
	ErrorStatusNoPropChanges

	// Comment errors
	ErrorStatusCommentTextInvalid
	ErrorStatusCommentParentIDInvalid
	ErrorStatusCommentVoteInvalid
	ErrorStatusCommentNotFound
	ErrorStatusCommentVoteChangesMax

	// Vote errors
	ErrorStatusVoteStatusInvalid
	ErrorStatusVoteParamsInvalid
	ErrorStatusBallotInvalid

	// Cast vote errors
	// TODO these need human readable equivalents
	VoteErrorInvalid             VoteErrorT = 0
	VoteErrorInternalError       VoteErrorT = 1
	VoteErrorTokenInvalid        VoteErrorT = 2
	VoteErrorRecordNotFound      VoteErrorT = 3
	VoteErrorMultipleRecordVotes VoteErrorT = 4
	VoteErrorVoteStatusInvalid   VoteErrorT = 5
	VoteErrorVoteBitInvalid      VoteErrorT = 6
	VoteErrorSignatureInvalid    VoteErrorT = 7
	VoteErrorTicketNotEligible   VoteErrorT = 8
	VoteErrorTicketAlreadyVoted  VoteErrorT = 9
)

var (
	// ErrorStatus contains human readable error messages.
	// TODO fill in error status messages
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:          "error status invalid",
		ErrorStatusInputInvalid:     "input invalid",
		ErrorStatusPageSizeExceeded: "page size exceeded",

		// User errors
		ErrorStatusUserRegistrationNotPaid: "user registration not paid",
		ErrorStatusUserBalanceInsufficient: "user balance insufficient",
		ErrorStatusUnauthorized:            "user is unauthorized",

		// Signature errors
		ErrorStatusPublicKeyInvalid: "public key invalid",
		ErrorStatusSignatureInvalid: "signature invalid",

		// Proposal errors
		ErrorStatusFileCountInvalid:              "file count invalid",
		ErrorStatusFileNameInvalid:               "file name invalid",
		ErrorStatusFileMIMEInvalid:               "file mime invalid",
		ErrorStatusFileDigestInvalid:             "file digest invalid",
		ErrorStatusFilePayloadInvalid:            "file payload invalid",
		ErrorStatusIndexFileNameInvalid:          "index filename invalid",
		ErrorStatusIndexFileCountInvalid:         "index file count invalid",
		ErrorStatusIndexFileSizeInvalid:          "index file size invalid",
		ErrorStatusTextFileCountInvalid:          "text file count invalid",
		ErrorStatusImageFileCountInvalid:         "file count invalid",
		ErrorStatusImageFileSizeInvalid:          "file size invalid",
		ErrorStatusMetadataCountInvalid:          "metadata count invalid",
		ErrorStatusMetadataDigestInvalid:         "metadata digest invalid",
		ErrorStatusMetadataPayloadInvalid:        "metadata pyaload invalid",
		ErrorStatusPropMetadataNotFound:          "proposal metadata not found",
		ErrorStatusPropNameInvalid:               "proposal name invalid",
		ErrorStatusPropLinkToInvalid:             "proposal link to invalid",
		ErrorStatusPropLinkByInvalid:             "proposal link by invalid",
		ErrorStatusPropTokenInvalid:              "proposal token invalid",
		ErrorStatusPropNotFound:                  "proposal not found",
		ErrorStatusPropStateInvalid:              "proposal state invalid",
		ErrorStatusPropStatusInvalid:             "proposal status invalid",
		ErrorStatusPropStatusChangeInvalid:       "proposal status change invalid",
		ErrorStatusPropStatusChangeReasonInvalid: "proposal status reason invalid",
		ErrorStatusNoPropChanges:                 "no proposal changes",

		// Comment errors
		ErrorStatusCommentTextInvalid:     "comment text invalid",
		ErrorStatusCommentParentIDInvalid: "comment parent ID invalid",
		ErrorStatusCommentVoteInvalid:     "comment vote invalid",
		ErrorStatusCommentNotFound:        "comment not found",
		ErrorStatusCommentVoteChangesMax:  "comment vote changes exceeded max",

		// Vote errors
		ErrorStatusVoteStatusInvalid: "vote status invalid",
		ErrorStatusVoteParamsInvalid: "vote params invalid",
		ErrorStatusBallotInvalid:     "ballot invalid",
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

// ProposalStatusSet sets the status of a proposal. Some status changes require
// a reason to be included.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type ProposalStatusSet struct {
	Token     string      `json:"token"`            // Censorship token
	State     PropStateT  `json:"state"`            // Proposal state
	Version   string      `json:"version"`          // Proposal version
	Status    PropStatusT `json:"status"`           // New status
	Reason    string      `json:"reason,omitempty"` // Reason for status change
	PublicKey string      `json:"publickey"`        // Key used for signature
	Signature string      `json:"signature"`        // Client signature
}

// ProposalStatusSetReply is the reply to the ProposalStatusSet command.
type ProposalStatusSetReply struct {
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
// requests. Unvetted proposals are stripped of their user defined proposal
// files and metadata when being returned to non-admins.
//
// IncludeFiles specifies whether the proposal files should be returned. The
// user defined metadata will still be returned even when IncludeFiles is set
// to false.
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

// ProposalInventory retrieves the tokens of all proposals in the inventory,
// categorized by proposal status and ordered by timestamp of the status change
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

// CommentVoteDetails represents all user generated data and server generated
// metadata for a comment vote.
type CommentVoteDetails struct {
	UserID    string       `json:"userid"`
	State     PropStateT   `json:"state"`
	Token     string       `json:"token"`
	CommentID uint32       `json:"commentid"`
	Vote      CommentVoteT `json:"vote"`
	PublicKey string       `json:"publickey"`
	Signature string       `json:"signature"`
	Timestamp int64        `json:"timestamp"`
	Receipt   string       `json:"receipt"`
}

// CommentVotes returns all comment votes that meet the provided filtering
// criteria.
type CommentVotes struct {
	State  PropStateT `json:"state"`
	Token  string     `json:"token"`
	UserID string     `json:"userid"`
}

// CommentVotesReply is the reply to the CommentVotes command.
type CommentVotesReply struct {
	Votes []CommentVoteDetails `json:"votes"`
}

// AuthorizeDetails contains the details of a vote authorization.
type AuthorizeDetails struct {
	Token     string `json:"token"`     // Proposal token
	Version   uint32 `json:"version"`   // Proposal version
	Action    string `json:"action"`    // Authorize or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of token+version+action
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// VoteOption describes a single vote option.
type VoteOption struct {
	ID          string `json:"id"`          // Single, unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bit         uint64 `json:"bit"`         // Bit used for this option
}

// VoteParams contains all client defined vote params required by server to
// start a proposal vote.
type VoteParams struct {
	Token    string `json:"token"`    // Proposal token
	Version  uint32 `json:"version"`  // Proposal version
	Type     VoteT  `json:"type"`     // Vote type
	Mask     uint64 `json:"mask"`     // Valid vote bits
	Duration uint32 `json:"duration"` // Duration in blocks

	// QuorumPercentage is the percent of elligible votes required for
	// the vote to meet a quorum.
	QuorumPercentage uint32 `json:"quorumpercentage"`

	// PassPercentage is the percent of total votes that are required
	// to consider a vote option as passed.
	PassPercentage uint32 `json:"passpercentage"`

	Options []VoteOption `json:"options"`
}

// VoteDetails contains the details of a proposal vote.
//
// Signature is the client signature of the SHA256 digest of the JSON encoded
// Vote struct.
type VoteDetails struct {
	Params           VoteParams `json:"params"`
	PublicKey        string     `json:"publickey"`
	Signature        string     `json:"signature"`
	StartBlockHeight uint32     `json:"startblockheight"`
	StartBlockHash   string     `json:"startblockhash"`
	EndBlockHeight   uint32     `json:"endblockheight"`
	EligibleTickets  []string   `json:"eligibletickets"` // Ticket hashes
}

// CastVoteDetails contains the details of a cast vote.
type CastVoteDetails struct {
	Token     string `json:"token"`     // Proposal token
	Ticket    string `json:"ticket"`    // Ticket hash
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// VoteResult describes a vote option and the total number of votes that have
// been cast for this option.
type VoteResult struct {
	ID          string `json:"id"`          // Single unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	VoteBit     uint64 `json:"votebit"`     // Bits used for this option
	Votes       uint64 `json:"votes"`       // Votes cast for this option
}

// VoteSummary summarizes the vote params and results of a proposal vote.
type VoteSummary struct {
	Type             VoteT        `json:"type"`
	Status           VoteStatusT  `json:"status"`
	Duration         uint32       `json:"duration"`
	StartBlockHeight uint32       `json:"startblockheight"`
	StartBlockHash   string       `json:"startblockhash"`
	EndBlockHeight   uint32       `json:"endblockheight"`
	EligibleTickets  uint32       `json:"eligibletickets"`
	QuorumPercentage uint32       `json:"quorumpercentage"`
	PassPercentage   uint32       `json:"passpercentage"`
	Results          []VoteResult `json:"results"`
	Approved         bool         `json:"approved"`
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

// VoteStart starts a proposal vote.  All proposal votes must be authorized
// by the proposal author before an admin is able to start the voting process.
//
// Signature is the signature of a SHA256 digest of the JSON encoded Vote
// structure.
type VoteStart struct {
	Params    VoteParams `json:"params"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// VoteStartReply is the reply to the VoteStart command.
type VoteStartReply struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// VoteStartRunoff starts a runoff vote between the provided submissions. Each
// submission is required to have its own Authorize and Start.
type VoteStartRunoff struct {
	Token  string          `json:"token"` // RFP token
	Auths  []VoteAuthorize `json:"auths"`
	Starts []VoteStart     `json:"starts"`
}

// VoteStartRunoffReply is the reply to the VoteStartRunoff command.
type VoteStartRunoffReply struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
}

// CastVote is a signed ticket vote.
type CastVote struct {
	Token     string `json:"token"`     // Proposal token
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// CastVoteReply contains the receipt for the cast vote.
type CastVoteReply struct {
	Ticket  string `json:"ticket"`  // Ticket ID
	Receipt string `json:"receipt"` // Server signature of client signature

	// The follwing fields will only be present if an error occurred
	// while attempting to cast the vote.
	ErrorCode    VoteErrorT `json:"errorcode,omitempty"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// VoteBallot is a batch of votes that are sent to the server. A ballot can only
// contain the votes for a single record.
type VoteBallot struct {
	Votes []CastVote `json:"votes"`
}

// VoteBallotReply is a reply to a batched list of votes.
type VoteBallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// ProposalVote contains all vote authorizations and the vote details for a
// proposal vote. The vote details will be null if the proposal vote has not
// been started yet.
type ProposalVote struct {
	Auths []AuthorizeDetails `json:"auths"`
	Vote  *VoteDetails       `json:"vote"`
}

// Votes returns the vote authorizations and vote details for each of the
// provided proposal tokens.
type Votes struct {
	Tokens []string `json:"tokens"`
}

// VotesReply is the reply to the Votes command. The returned map will not
// contain an entry for any tokens that did not correspond to an actual
// proposal. It is the callers responsibility to ensure that a entry is
// returned for all of the provided tokens.
type VotesReply struct {
	Votes map[string]ProposalVote `json:"votes"`
}

// VoteResults returns the votes that have been cast for the specified
// proposal.
type VoteResults struct {
	Token string `json:"token"`
}

// VoteResultsReply is the reply to the VoteResults command.
type VoteResultsReply struct {
	Votes []CastVoteDetails `json:"votes"`
}

// VoteSummaries summarizes the vote params and results for a ticket vote.
type VoteSummaries struct {
	Tokens []string `json:"tokens"`
}

// VoteSummariesReply is the reply to the VoteSummaries command.
//
// Summaries field contains a vote summary for each of the provided
// tokens. The map will not contain an entry for any tokens that
// did not correspond to an actual record. It is the callers
// responsibility to ensure that a summary is returned for all of
// the provided tokens.
type VoteSummariesReply struct {
	Summaries map[string]VoteSummary `json:"summaries"` // [token]Summary

	// BestBlock is the best block value that was used to prepare the
	// summaries.
	BestBlock uint32 `json:"bestblock"`
}

// VoteInventory retrieves the tokens of all public, non-abandoned proposals
// categorized by their vote status.
type VoteInventory struct{}

// VoteInventoryReply in the reply to the VoteInventory command.
type VoteInventoryReply struct {
	Unauthorized []string `json:"unauthorized"`
	Authorized   []string `json:"authorized"`
	Started      []string `json:"started"`
	Approved     []string `json:"approved"`
	Rejected     []string `json:"rejected"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}
