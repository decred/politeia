// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a politeiad plugin for functionality that is specific to
// decred's proposal system.
package pi

type PropStatusT int
type ErrorStatusT int

const (
	ID = "pi"

	// Plugin commands
	CmdProposalInv   = "proposalinv" // Get inventory by proposal status
	CmdVoteInventory = "voteinv"     // Get inventory by vote status

	// TODO get rid of CmdProposals
	CmdProposals = "proposals" // Get plugin data for proposals

	// Metadata stream IDs
	MDStreamIDGeneralMetadata = 1
	MDStreamIDStatusChanges   = 2

	// FileNameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameProposalMetadata = "proposalmetadata.json"

	// Proposal status codes
	PropStatusInvalid   PropStatusT = 0 // Invalid status
	PropStatusUnvetted  PropStatusT = 1 // Prop has not been vetted
	PropStatusPublic    PropStatusT = 2 // Prop has been made public
	PropStatusCensored  PropStatusT = 3 // Prop has been censored
	PropStatusAbandoned PropStatusT = 4 // Prop has been abandoned

	// User error status codes
	// TODO number error codes and add human readable error messages
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusPageSizeExceeded ErrorStatusT = iota
	ErrorStatusPropNotFound
	ErrorStatusPropStateInvalid
	ErrorStatusPropTokenInvalid
	ErrorStatusPropStatusInvalid
	ErrorStatusPropVersionInvalid
	ErrorStatusPropStatusChangeInvalid
	ErrorStatusPropLinkToInvalid
	ErrorStatusVoteStatusInvalid
	ErrorStatusStartDetailsInvalid
	ErrorStatusStartDetailsMissing
	ErrorStatusVoteParentInvalid
	ErrorStatusLinkByNotExpired
)

var (
	// PropStatuses contains the human readable proposal statuses.
	PropStatuses = map[PropStatusT]string{
		PropStatusInvalid:   "invalid",
		PropStatusUnvetted:  "unvetted",
		PropStatusPublic:    "public",
		PropStatusCensored:  "censored",
		PropStatusAbandoned: "abandoned",
	}

	// StatusChanges contains the allowed proposal status change
	// transitions. If StatusChanges[currentStatus][newStatus] exists
	// then the status change is allowed.
	StatusChanges = map[PropStatusT]map[PropStatusT]struct{}{
		PropStatusUnvetted: {
			PropStatusPublic:   {},
			PropStatusCensored: {},
		},
		PropStatusPublic: {
			PropStatusAbandoned: {},
			PropStatusCensored:  {},
		},
		PropStatusCensored:  {},
		PropStatusAbandoned: {},
	}
)

// ProposalMetadata contains metadata that is provided by the user as part of
// the proposal submission bundle. The proposal metadata is included in the
// proposal signature since it is user specified data. The ProposalMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
type ProposalMetadata struct {
	// Name is the name of the proposal.
	Name string `json:"name"`

	// LinkTo specifies a public proposal token to link this proposal
	// to. Ex, an RFP sumbssion must link to the RFP proposal.
	LinkTo string `json:"linkto,omitempty"`

	// LinkBy is a UNIX timestamp that serves as a deadline for other
	// proposals to link to this proposal. Ex, an RFP submission cannot
	// link to an RFP proposal once the RFP's LinkBy deadline is past.
	LinkBy int64 `json:"linkby,omitempty"`
}

// GeneralMetadata contains general metadata about a politeiad record. It is
// saved to politeiad as a metadata stream.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all politeiad Files.
type GeneralMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
	Timestamp int64  `json:"timestamp"` // Submission UNIX timestamp
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

// Proposals requests the plugin data for the provided proposals. This includes
// pi plugin data as well as other plugin data such as comment plugin data.
// This command aggregates all proposal plugin data into a single call.
type Proposals struct {
	Tokens []string `json:"tokens"`
}

// ProposalPluginData contains all the plugin data for a proposal.
type ProposalPluginData struct {
	Comments   uint64   `json:"comments"`   // Number of comments
	LinkedFrom []string `json:"linkedfrom"` // Linked from list
}

// ProposalsReply is the reply to the Proposals command. The proposals map will
// not contain an entry for tokens that do not correspond to actual proposals.
type ProposalsReply struct {
	Proposals map[string]ProposalPluginData `json:"proposals"`
}

// ProposalInv retrieves the tokens of all proposals in the inventory that
// match the provided filtering criteria. The returned proposals are
// categorized by proposal state and status. If no filtering criteria is
// provided then the full proposal inventory is returned.
type ProposalInv struct {
	UserID string `json:"userid,omitempty"`
}

// ProposalInvReply is the reply to the ProposalInv command. The returned maps
// contains map[status][]token where the status is the human readable proposal
// status and the token is the proposal token.
type ProposalInvReply struct {
	Unvetted map[string][]string `json:"unvetted"`
	Vetted   map[string][]string `json:"vetted"`
}

// VoteInventory requests the tokens of all proposals in the inventory
// categorized by their vote status. This call relies on the ticketvote
// Inventory call, but breaks the Finished vote status out into Approved and
// Rejected categories. This functionality is specific to pi.
type VoteInventory struct{}

// VoteInventoryReply is the reply to the VoteInventory command.
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
