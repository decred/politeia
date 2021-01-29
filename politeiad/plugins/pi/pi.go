// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a plugin for functionality that is specific to decred's
// proposal system.
package pi

const (
	// PluginID is the pi plugin ID.
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
