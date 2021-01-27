// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a plugin for functionality that is specific to decred's
// proposal system.
package pi

const (
	PluginID = "pi"

	// Plugin commands
	CmdVoteInv = "voteinv" // Get inventory by vote status
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT int

const (
	// TODO number error codes
	ErrorCodeInvalid          ErrorCodeT = 0
	ErrorCodePageSizeExceeded ErrorCodeT = iota
	ErrorCodeFileNameInvalid
	ErrorCodeIndexFileNameInvalid
	ErrorCodeIndexFileCountInvalid
	ErrorCodeIndexFileSizeInvalid
	ErrorCodeTextFileCountInvalid
	ErrorCodeImageFileCountInvalid
	ErrorCodeImageFileSizeInvalid
	ErrorCodeProposalMetadataInvalid
	ErrorCodeProposalNameInvalid
	ErrorCodeVoteStatusInvalid
)

var (
	// TODO ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid: "error code invalid",
	}
)

const (
	// FileNameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameProposalMetadata = "proposalmetadata.json"
)

// ProposalMetadata contains metadata that is provided by the user as part of
// the proposal submission bundle. The proposal metadata is included in the
// proposal signature since it is user specified data. The ProposalMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
type ProposalMetadata struct {
	Name string `json:"name"`
}

// PropStatusT represents a proposal status. These map directly to the
// politeiad record statuses, but some have had their names changed to better
// reflect their intended use case by proposals.
type PropStatusT int

const (
	// PropStatusInvalid is an invalid proposal status.
	PropStatusInvalid PropStatusT = 0

	// PropStatusUnreviewed indicates the proposal has been submitted,
	// but has not yet been reviewed and made public by an admin. A
	// proposal with this status will have a proposal state of
	// PropStateUnvetted.
	PropStatusUnvetted PropStatusT = 1

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

	// PropStatusUnreviewedChanges is a deprecated proposal status that
	// has only been included so that the proposal statuses map
	// directly to the politeiad record statuses.
	PropStatusUnreviewedChanges PropStatusT = 4

	// PropStatusAbandoned indicates that a proposal has been marked
	// as abandoned by an admin due to the author being inactive.
	PropStatusAbandoned PropStatusT = 5
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
)

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
