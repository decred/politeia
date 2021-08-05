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

	// RouteBillingStatus sets the record's billing status.
	RouteBillingStatus = "/billingstatus"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// Error codes
	ErrorCodeInvalid          ErrorCodeT = 0
	ErrorCodeInputInvalid     ErrorCodeT = 1
	ErrorCodePublicKeyInvalid ErrorCodeT = 2
	ErrorCodeLast             ErrorCodeT = 3
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:          "error invalid",
		ErrorCodeInputInvalid:     "input invalid",
		ErrorCodePublicKeyInvalid: "public key invalid",
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
type PolicyReply struct {
	TextFileSizeMax    uint32   `json:"textfilesizemax"` // In bytes
	ImageFileCountMax  uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax   uint32   `json:"imagefilesizemax"` // In bytes
	NameLengthMin      uint32   `json:"namelengthmin"`    // In characters
	NameLengthMax      uint32   `json:"namelengthmax"`    // In characters
	NameSupportedChars []string `json:"namesupportedchars"`
	AmountMin          uint64   `json:"amountmin"`    // In cents
	AmountMax          uint64   `json:"amountmax"`    // In cents
	StartDateMin       int64    `json:"startdatemin"` // Seconds from current time
	EndDateMax         int64    `json:"enddatemax"`   // Seconds from current time
	Domains            []string `json:"domains"`
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
// approved by the Decrd stakeholders.
type BillingStatusT uint32

const (
	// BillingStatusInvalid is an invalid billing status.
	BillingStatusInvalid BillingStatusT = 0

	// BillingStatusClosed represents a proposal that was approved by
	// the Decred stakeholders, but has been closed by an admin prior
	// to the proposal being completed. The most common reason for this
	// is because a proposal author failed to deliver on the work that
	// was funded in the proposal. A closed proposal can no longer be
	// billed against.
	BillingStatusClosed BillingStatusT = 1

	// BillingStatusCompleted represents a proposal that was approved
	// by the Decred stakeholders and has been successfully completed.
	// A completed proposal can no longer be billed against. A proposal
	// is marked as completed by an admin.
	BillingStatusCompleted BillingStatusT = 2
)

// BillingStatusChange represents the structure that is saved to disk when
// a proposal has its billing status updated. Some billing status changes
// require a reason to be given.
//
// Signature is the admin signature of the Token+Status+Reason.
type BillingStatusChange struct {
	Token     string         `json:"token"`
	Status    BillingStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
	Timestamp int64          `json:"timestamp"`
}

// SetBillingStatus sets the billing status of a proposal. Some billing status
// changes require a reason to be given.
//
// Signature is the admin signature of the Token+Status+Reason.
type SetBillingStatus struct {
	Token     string         `json:"token"`
	Status    BillingStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
}

// SetBillingStatusReply is the reply to the SetBillingStatus command.
type SetBillingStatusReply struct {
	Timestamp int64 `json:"timestamp"`
}
