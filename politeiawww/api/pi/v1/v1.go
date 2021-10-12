// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// RoutePolicy returns the policy for the pi API.
	RoutePolicy = "/policy"

	// RouteSetBillingStatus sets the proposal's billing status.
	RouteSetBillingStatus = "/setbillingstatus"

	// RouteBillingStatusChanges returns the proposal's billing status changes.
	RouteBillingStatusChanges = "/billingstatuschanges"

	// RouteSummaries returns the proposal summary for a page of
	// records.
	RouteSummaries = "/summaries"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeInputInvalid is returned when there is an error
	// while prasing a command payload.
	ErrorCodeInputInvalid ErrorCodeT = 1

	// ErrorCodePublicKeyInvalid is returned when a public key is
	// invalid.
	ErrorCodePublicKeyInvalid ErrorCodeT = 2

	// ErrorCodeRecordTokenInvalid is returned when a record token is
	// invalid.
	ErrorCodeRecordTokenInvalid ErrorCodeT = 3

	// ErrorCodeRecordNotFound is returned when no record was found.
	ErrorCodeRecordNotFound ErrorCodeT = 4

	// ErrorCodePageSizeExceeded is returned when the request's page size
	// exceeds the maximum page size of the request.
	ErrorCodePageSizeExceeded ErrorCodeT = 5

	// ErrorCodeLast is used by unit tests to verify that all error codes have
	// a human readable entry in the ErrorCodes map. This error will never be
	// returned.
	ErrorCodeLast ErrorCodeT = 6
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:            "error invalid",
		ErrorCodeInputInvalid:       "input invalid",
		ErrorCodePublicKeyInvalid:   "public key invalid",
		ErrorCodeRecordTokenInvalid: "record token invalid",
		ErrorCodeRecordNotFound:     "record not found",
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

// Policy requests the policy settings for the pi API. It includes the policy
// guidlines for the contents of a proposal record.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
//
// NOTE: NameLengthMin, NameLengthMax, NameSupportedChars are not consistent
// with the field names in the pi plugin where they defined as titleLengthMin,
// titleLengthMax & titleSupportedChars as they are now used to verify both
// the proposal name and the proposal author update title.
// We have not updated the field names here to avoid introducing breaking
// changes.
type PolicyReply struct {
	TextFileSizeMax              uint32   `json:"textfilesizemax"` // In bytes
	ImageFileCountMax            uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax             uint32   `json:"imagefilesizemax"` // In bytes
	NameLengthMin                uint32   `json:"namelengthmin"`    // In characters
	NameLengthMax                uint32   `json:"namelengthmax"`    // In characters
	NameSupportedChars           []string `json:"namesupportedchars"`
	AmountMin                    uint64   `json:"amountmin"`    // In cents
	AmountMax                    uint64   `json:"amountmax"`    // In cents
	StartDateMin                 int64    `json:"startdatemin"` // Seconds from current time
	EndDateMax                   int64    `json:"enddatemax"`   // Seconds from current time
	Domains                      []string `json:"domains"`
	SummariesPageSize            uint32   `json:"summariespagesize"`
	BillingStatusChangesPageSize uint32   `json:"billingstatuschangespagesize"`
	BillingStatusChangesMax      uint32   `json:"billingstatuschangesmax"`
}

const (
	// FileNameIndexFile is the file name of the proposal markdown
	// file that contains the main proposal contents. All proposal
	// submissions must contain an index file.
	FileNameIndexFile = "index.md"

	// FileNameProposalMetadata is the file name of the user submitted
	// ProposalMetadata. All proposal submissions must contain a
	// proposal metadata file.
	FileNameProposalMetadata = "proposalmetadata.json"

	// FileNameVoteMetadata is the file name of the user submitted
	// VoteMetadata. This file will only be present when proposals
	// are hosting or participating in certain types of votes.
	FileNameVoteMetadata = "votemetadata.json"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission.
type ProposalMetadata struct {
	Name      string `json:"name"`      // Proposal name
	Amount    uint64 `json:"amount"`    // Funding amount in cents
	StartDate int64  `json:"startdate"` // Start date, Unix time
	EndDate   int64  `json:"enddate"`   // Estimated end date, Unix time
	Domain    string `json:"domain"`    // Proposal domain
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

// BillingStatusT represents the billing status of a proposal that has been
// approved by the Decred stakeholders.
type BillingStatusT uint32

const (
	// BillingStatusInvalid is an invalid billing status.
	BillingStatusInvalid BillingStatusT = 0

	// BillingStatusActive represents a proposal that was approved by
	// the Decred stakeholders and is being actively billed against.
	BillingStatusActive BillingStatusT = 1

	// BillingStatusClosed represents a proposal that was approved by
	// the Decred stakeholders, but has been closed by an admin prior
	// to the proposal being completed. The most common reason for this
	// is because a proposal author failed to deliver on the work that
	// was funded in the proposal. A closed proposal can no longer be
	// billed against.
	BillingStatusClosed BillingStatusT = 2

	// BillingStatusCompleted represents a proposal that was approved
	// by the Decred stakeholders and has been successfully completed.
	// A completed proposal can no longer be billed against. A proposal
	// is marked as completed by an admin.
	BillingStatusCompleted BillingStatusT = 3

	// BillingStatusLast unit test only.
	BillingStatusLast BillingStatusT = 4
)

var (
	// BillingStatuses contains the human readable billing statuses.
	BillingStatuses = map[BillingStatusT]string{
		BillingStatusInvalid:   "invalid",
		BillingStatusActive:    "active",
		BillingStatusClosed:    "closed",
		BillingStatusCompleted: "completed",
	}
)

// BillingStatusChange represents the structure that is saved to disk when
// a proposal has its billing status updated. Some billing status changes
// require a reason to be given. Only admins can update the billing status
// of a proposal.
//
// PublicKey is the admin public key that can be used to verify the signature.
//
// Signature is the admin signature of the Token+Status+Reason.
//
// Receipt is the server signature of the admin signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type BillingStatusChange struct {
	Token     string         `json:"token"`
	Status    BillingStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
	Receipt   string         `json:"receipt"`
	Timestamp int64          `json:"timestamp"` // Unix timestamp
}

// SetBillingStatus sets the billing status of a proposal. Some billing status
// changes require a reason to be given. Only admins can update the billing
// status of a proposal.
//
// PublicKey is the admin public key that can be used to verify the signature.
//
// Signature is the admin signature of the Token+Status+Reason.
//
// The PublicKey and Signature are hex encoded and use the ed25519 signature
// scheme.
type SetBillingStatus struct {
	Token     string         `json:"token"`
	Status    BillingStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
}

// SetBillingStatusReply is the reply to the SetBillingStatus command.
//
// Receipt is the server signature of the client signature. It is hex encoded
// and uses the ed25519 signature scheme.
type SetBillingStatusReply struct {
	Receipt   string `json:"receipt"`
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

const (
	// BillingStatusChangesPageSize is the maximum number of billing status
	// changes that can be requested at any one time.
	BillingStatusChangesPageSize uint32 = 5
)

// BillingStatusChanges requests the billing status changes for the provided
// proposal tokens.
type BillingStatusChanges struct {
	Tokens []string `json:"tokens"`
}

// BillingStatusChangesReply is the reply to the BillingStatusChanges command.
//
// BillingStatusChanges contains the billing status changes for each of the
// provided tokens. The map will not contain an entry for any tokens that
// did not correspond to an actual proposal. It is the callers responsibility
// to ensure that the billing status changes are returned for all provided
// tokens.
type BillingStatusChangesReply struct {
	BillingStatusChanges map[string][]BillingStatusChange `json:"billingstatuschanges"`
}

const (
	// ProposalUpdateHint is the hint that is included in a comment's
	// ExtraDataHint field to indicate that the comment is an update
	// from the proposal author.
	ProposalUpdateHint = "proposalupdate"
)

// ProposalUpdateMetadata contains the metadata that is attached to a comment
// in the comment's ExtraData field to indicate that the comment is an update
// from the proposal author.
type ProposalUpdateMetadata struct {
	Title string `json:"title"`
}

const (
	// SummariesPageSize is the maximum number of proposal summaries that
	// can be requested at any one time.
	SummariesPageSize uint32 = 5
)

// Summaries requests the proposal summaries for the provided proposal tokens.
type Summaries struct {
	Tokens []string `json:"tokens"`
}

// SummariesReply is the reply to the Summaries command.
//
// Summaries field contains a proposal summary for each of the provided tokens.
// The map will not contain an entry for any tokens that did not correspond
// to an actual proposal. It is the callers responsibility to ensure that a
// summary is returned for all provided tokens.
type SummariesReply struct {
	Summaries map[string]Summary `json:"summaries"` // [token]Summary
}

// Summary summarizes proposal information.
//
// Status field is the string value of the PropStatusT type which is defined
// along with all of it's possible values in the pi plugin API.
type Summary struct {
	Status string `json:"status"`
}
