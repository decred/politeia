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
	CmdVoteInv = "voteinv"

	// Setting keys are the plugin setting keys that can be used to
	// override a default plugin setting. Defaults will be overridden
	// if a plugin setting is provided to the plugin on startup.
	SettingKeyTextFileSizeMax            = "textfilesizemax"
	SettingKeyImageFileCountMax          = "imagefilecountmax"
	SettingKeyImageFileSizeMax           = "imagefilesizemax"
	SettingKeyProposalNameLengthMin      = "proposalnamelengthmin"
	SettingKeyProposalNameLengthMax      = "proposalnamelengthmax"
	SettingKeyProposalNameSupportedChars = "proposalnamesupportedchars"

	// SettingTextFileSizeMax is the default maximum allowed size of a
	// text file in bytes.
	SettingTextFileSizeMax uint32 = 512 * 1024

	// SettingImageFileCountMax is the default maximum number of image
	// files that can be included in a proposal.
	SettingImageFileCountMax uint32 = 5

	// SettingImageFileSizeMax is the default maximum allowed size of
	// an image file in bytes.
	SettingImageFileSizeMax uint32 = 512 * 1024

	// SettingProposalNameLengthMin is the default minimum number of
	// characters that a proposal name can be.
	SettingProposalNameLengthMin uint32 = 8

	// SettingProposalNameLengthMax is the default maximum number of
	// characters that a proposal name can be.
	SettingProposalNameLengthMax uint32 = 80
)

var (
	// SettingProposalNameSupportedChars contains the supported
	// characters in a proposal name.
	SettingProposalNameSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#",
		"/", "(", ")", "!", "?", "\"", "'",
	}
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT int

const (
	// ErrorCodeInvalid represents and invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeTextFileNameInvalid is returned when a text file has
	// a file name that is not allowed.
	ErrorCodeTextFileNameInvalid ErrorCodeT = 1

	// ErrorCodeTextFileSizeInvalid is returned when a text file size
	// exceedes the TextFileSizeMax setting.
	ErrorCodeTextFileSizeInvalid ErrorCodeT = 2

	// ErrorCodeTextFileMissing is returned when the proposal does not
	// contain one or more of the required text files.
	ErrorCodeTextFileMissing ErrorCodeT = 3

	// ErrorCodeImageFileCountInvalid is returned when the number of
	// image attachments exceedes the ImageFileCountMax setting.
	ErrorCodeImageFileCountInvalid ErrorCodeT = 4

	// ErrorCodeImageFileSizeInvalid is returned when an image file
	// size exceedes the ImageFileSizeMax setting.
	ErrorCodeImageFileSizeInvalid ErrorCodeT = 5

	// ErrorCodeProposalNameInvalid is returned when a proposal name
	// does not adhere to the proposal name settings.
	ErrorCodeProposalNameInvalid ErrorCodeT = 6

	// ErrorCodeVoteStatusInvalid is returned when a proposal vote
	// status does not allow changes to be made to the proposal.
	ErrorCodeVoteStatusInvalid ErrorCodeT = 7
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:               "error code invalid",
		ErrorCodeTextFileNameInvalid:   "text file name invalid",
		ErrorCodeTextFileSizeInvalid:   "text file size invalid",
		ErrorCodeTextFileMissing:       "text file is misisng",
		ErrorCodeImageFileCountInvalid: "image file count invalid",
		ErrorCodeImageFileSizeInvalid:  "image file size invalid",
		ErrorCodeProposalNameInvalid:   "proposal name invalid",
		ErrorCodeVoteStatusInvalid:     "vote status invalid",
	}
)

const (
	// FileNameIndexFile is the file name of the proposal markdown
	// file. Every proposal is required to have an index file. The
	// index file should contain the proposal content.
	FileNameIndexFile = "index.md"

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
