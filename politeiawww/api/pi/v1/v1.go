// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
)

// TODO verify that all batched request have a page size limit
// TODO module these API packages

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// Routes
	RoutePolicy        = "/policy"
	RouteProposals     = "/proposals"
	RouteVoteInventory = "/voteinventory"

	// Proposal states
	ProposalStateUnvetted = "unvetted"
	ProposalStateVetted   = "vetted"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT int

const (
	// Error status codes
	ErrorCodeInvalid              ErrorCodeT = 0
	ErrorCodeInputInvalid         ErrorCodeT = 1
	ErrorCodePageSizeExceeded     ErrorCodeT = 2
	ErrorCodeProposalStateInvalid ErrorCodeT = 3
)

var (
	// ErrorCodes contains human readable error messages.
	// TODO fill in error status messages
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:          "error status invalid",
		ErrorCodeInputInvalid:     "input invalid",
		ErrorCodePageSizeExceeded: "page size exceeded",
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

// Policy requests the policy settings for the pi API. It includes the policy
// guidlines for the contents of a proposal record.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
type PolicyReply struct {
	TextFileSizeMax    uint32   `json:"textfilesizemax"` // In bytes
	ImageFileCountMax  uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax   uint32   `json:"imagefilesizemax"` // In bytes
	NameLengthMin      uint32   `json:"namelengthmin"`    // In characters
	NameLengthMax      uint32   `json:"namelengthmax"`    // In characters
	NameSupportedChars []string `json:"namesupportedchars"`
}

// PropStatusT represents a proposal status. The proposal status codes map
// directly to the record status codes. Some have been renamed to give a more
// accurate representation of their use in pi.
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
	// by an admin for violating the proposal guidlines. Both unvetted
	// and vetted proposals can be censored so a proposal with this
	// status can have a state of either PropStateUnvetted or
	// PropStateVetted depending on whether the proposal was censored
	// before or after it was made public.
	PropStatusCensored PropStatusT = 3

	// PropStatusUnreviewedChanges is deprecated. It is only here so
	// the proposal status numbering maps directly to the record status
	// numbering.
	PropStatusUnreviewedChanges PropStatusT = 4

	// PropStatusAbandoned indicates that a proposal has been marked
	// as abandoned by an admin due to the author being inactive.
	PropStatusAbandoned PropStatusT = 5
)

const (
	// FileNameIndexFile is the file name of the proposal markdown
	// file that contains the proposal contents.
	FileNameIndexFile = "index.md"

	// FileNameProposalMetadata is the file name of the user submitted
	// ProposalMetadata.
	FileNameProposalMetadata = "proposalmetadata.json"

	// FileNameVoteMetadata is the file name of the user submitted
	// VoteMetadata.
	FileNameVoteMetadata = "votemetadata.json"
)

// File describes an individual file that is part of the proposal. The
// directory structure must be flattened.
type File struct {
	Name    string `json:"name"`    // Filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // File content, base64 encoded
}

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission.
type ProposalMetadata struct {
	Name string `json:"name"` // Proposal name
}

// VoteMetadata is metadata that is specified by the user on proposal
// submission in order to host or participate in a runoff vote.
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

// Proposal represents a proposal submission and its metadata.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal files.
type Proposal struct {
	Version   string         `json:"version"`   // Proposal version
	Timestamp int64          `json:"timestamp"` // Submission UNIX timestamp
	State     string         `json:"state"`     // Proposal state
	Status    PropStatusT    `json:"status"`    // Proposal status
	UserID    string         `json:"userid"`    // Author ID
	Username  string         `json:"username"`  // Author username
	PublicKey string         `json:"publickey"` // Key used in signature
	Signature string         `json:"signature"` // Signature of merkle root
	Files     []File         `json:"files"`     // Proposal files
	Statuses  []StatusChange `json:"statuses"`  // Status change history

	// CensorshipRecord contains cryptographic proof that the proposal
	// was received and processed by the server.
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

const (
	// ProposalsPageSize is the maximum number of proposals that can be
	// requested in a Proposals request.
	ProposalsPageSize = 10
)

// Proposals retrieves the Proposal for each of the provided tokens.
//
// This command does not return the proposal index file or any attachment
// files. It will return the ProposalMetadata file and the VoteMetadata file if
// one is present. Unvetted proposals are stripped of all user submitted data
// when being returned to non-admins.
type Proposals struct {
	State  string   `json:"state"`
	Tokens []string `json:"tokens"`
}

// ProposalsReply is the reply to the Proposals command. Any tokens that did
// not correspond to a Proposal will not be included in the reply.
type ProposalsReply struct {
	Proposals map[string]Proposal `json:"proposals"` // [token]Proposal
}

// VoteInventory retrieves the tokens of all public, non-abandoned proposals
// categorized by their vote status. This is the same inventory as the
// ticketvote API returns except the Finished vote status is broken out into
// Approved and Rejected.
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
