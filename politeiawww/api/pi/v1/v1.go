// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// RoutePolicy returns the policy for the pi API.
	RoutePolicy = "/policy"
)

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
	AmountMin          uint32   `json:"amountmin"`  // In cents
	AmountMax          uint32   `json:"amountmax"`  // In cents
	EndDateMax         uint64   `json:"enddatemax"` // Seconds from current time
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
