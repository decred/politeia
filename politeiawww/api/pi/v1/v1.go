// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
)

// TODO verify that all batched request have a page size limit
// TODO pi needs a Version route that returns the APIs and versions that pi
// uses.
// TODO new APIs need a Policy route. The policies should be defined in the
// plugin packages as plugin settings and returned in a policy command.
// TODO module these API packages

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// Proposal routes
	RouteProposalNew       = "/proposal/new"
	RouteProposalEdit      = "/proposal/edit"
	RouteProposalSetStatus = "/proposal/setstatus"
	RouteProposals         = "/proposals"
	RouteProposalInventory = "/proposals/inventory"

	// Vote routes
	RouteVoteInventory = "/votes/inventory"
)

// ErrorStatusT represents a user error status code.
type ErrorStatusT int

const (
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
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorStatusT `json:"errorcode"`
	ErrorContext string       `json:"errorcontext"`
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

// PropStateT represents a proposal state. A proposal state can be either
// unvetted or vetted. The PropStatusT type further breaks down these two
// states into more granular statuses.
type PropStateT int

const (
	// PropStateInvalid indicates an invalid proposal state.
	PropStateInvalid PropStateT = 0

	// PropStateUnvetted indicates a proposal has not been made public
	// yet. Only admins and the proposal author are able to view
	// unvetted proposals.
	PropStateUnvetted PropStateT = 1

	// PropStateVetted indicates a proposal has been made public.
	PropStateVetted PropStateT = 2
)

// PropStatusT represents a proposal status.
type PropStatusT int

const (
	// PropStatusInvalid indicates the proposal status is invalid.
	PropStatusInvalid PropStatusT = 0

	// PropStatusUnreviewed indicates the proposal has been submitted,
	// but has not yet been reviewed and made public by an admin. A
	// proposal with this status will have a proposal state of
	// PropStateUnvetted.
	PropStatusUnreviewed PropStatusT = 1

	// PropStatusPublic indicates that a proposal has been reviewed and
	// made public by an admin. A proposal with this status will have
	// a proposal state of PropStateVetted.
	PropStatusPublic PropStatusT = 2

	// PropStatusCensored indicates that a proposal has been censored
	// by an admin for violating the proposal guidlines.. Both unvetted
	// and vetted proposals can be censored so a proposal with this
	// status can have a state of either PropStateUnvetted or
	// PropStateVetted depending on whether the proposal was censored
	// before or after it was made public.
	PropStatusCensored PropStatusT = 3

	// PropStatusAbandoned indicates that a proposal has been marked
	// as abandoned by an admin due to the author being inactive.
	// TODO can a unvetted proposal be abandoned?
	PropStatusAbandoned PropStatusT = 4
)

// PropStatuses contains the human readable proposal statuses.
var PropStatuses = map[PropStatusT]string{
	PropStatusInvalid:    "invalid",
	PropStatusUnreviewed: "unreviewed",
	PropStatusPublic:     "public",
	PropStatusCensored:   "censored",
	PropStatusAbandoned:  "abandoned",
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

const (
	// HintProposalMetadata is the Metadata object hint that is used
	// when the payload contains a ProposalMetadata.
	HintProposalMetadata = "proposalmd"

	// HintVoteMetadata is the Metadata object hint that is used when
	// the payload contains a VoteMetadata.
	HintVoteMetadata = "votemd"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission. It is attached to a proposal submission as a Metadata object.
type ProposalMetadata struct {
	Name string `json:"name"` // Proposal name
}

// VoteMetadata that is specified by the user on proposal submission in order to
// host or participate in certain types of votes. It is attached to a proposal
// submission as a Metadata object.
type VoteMetadata struct {
	// LinkBy is set when the user intends for the proposal to be the
	// parent proposal in a runoff vote. It is a UNIX timestamp that
	// serves as the deadline for other proposals to declare their
	// intent to participate in the runoff vote.
	LinkBy int64 `json:"linkby,omitempty"`

	// LinkTo is the censorship token of a runoff vote parent proposal.
	// It is set when a proposal is being submitted as a vote options
	// in the runoff vote.
	LinkTo string `json:"linkto,omitempty"`
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

// ProposalRecord represents a proposal submission and its metadata.
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
	Files     []File         `json:"files"`     // Proposal files
	Metadata  []Metadata     `json:"metadata"`  // User defined metadata
	Statuses  []StatusChange `json:"statuses"`  // Status change history

	// CensorshipRecord contains cryptographic proof that the proposal
	// was received and processed by the server.
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
	Proposal ProposalRecord `json:"proposal"`
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
	Proposal ProposalRecord `json:"proposal"`
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
	Proposal ProposalRecord `json:"proposal"`
}

// ProposalRequest is used to request the ProposalRecord of the provided
// proposal token and version. If the version is omitted, the most recent
// version will be returned.
type ProposalRequest struct {
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
}

// Proposals retrieves the ProposalRecord for each of the provided proposal
// requests. Unvetted proposals are stripped of their user defined files and
// metadata when being returned to non-admins.
//
// IncludeFiles specifies whether the proposal files should be returned. The
// user defined metadata will still be returned even when IncludeFiles is set
// to false.
type Proposals struct {
	State        PropStateT        `json:"state"`
	Requests     []ProposalRequest `json:"requests,omitempty"`
	IncludeFiles bool              `json:"includefiles,omitempty"`
}

// ProposalsReply is the reply to the Proposals command. Any tokens that did
// not correspond to a ProposalRecord will not be included in the reply.
type ProposalsReply struct {
	Proposals map[string]ProposalRecord `json:"proposals"` // [token]Proposal
}

// ProposalInventory retrieves the tokens of all proposals in the inventory,
// categorized by proposal state and proposal status, that match the provided
// filtering criteria. If no filtering criteria is provided then the full
// proposal inventory is returned. Unvetted proposal tokens are only returned
// to admins and the proposal author.
type ProposalInventory struct {
	UserID string `json:"userid,omitempty"`
}

// ProposalInventoryReply is the reply to the ProposalInventory command. The
// inventory maps contain map[status][]tokens where the status is the human
// readable proposal status, as defined by the PropStatuses map, and the tokens
// are a list of proposal tokens for that status. Each list is ordered by
// timestamp of the status change from newest to oldest.
type ProposalInventoryReply struct {
	Unvetted map[string][]string `json:"unvetted"`
	Vetted   map[string][]string `json:"vetted"`
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
