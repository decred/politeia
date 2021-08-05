// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a plugin that extends records with functionality for
// decred's proposal system.
package pi

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "pi"

	// CmdBillingStatus command sets the billing status
	CmdBillingStatus = "billingstatus"
)

// Plugin setting keys can be used to specify custom plugin settings. Default
// plugin setting values can be overridden by providing a plugin setting key
// and value to the plugin on startup.
const (
	// SettingKeyTextFileSizeMax is the plugin setting key for the
	// SettingTextFileSizeMax plugin setting.
	SettingKeyTextFileSizeMax = "textfilesizemax"

	// SettingKeyImageFileCountMax is the plugin setting key for the
	// SettingImageFileCountMax plugin setting.
	SettingKeyImageFileCountMax = "imagefilecountmax"

	// SettingKeyImageFileSizeMax is the plugin setting key for the
	// SettingImageFileSizeMax plugin setting.
	SettingKeyImageFileSizeMax = "imagefilesizemax"

	// SettingKeyProposalNameLengthMin is the plugin setting key for
	// the SettingProposalNameLengthMin plugin setting.
	SettingKeyProposalNameLengthMin = "proposalnamelengthmin"

	// SettingKeyProposalNameLengthMax is the plugin setting key for
	// the SettingProposalNameLengthMax plugin setting.
	SettingKeyProposalNameLengthMax = "proposalnamelengthmax"

	// SettingKeyProposalNameSupportedChars is the plugin setting key
	// for the SettingProposalNameSupportedChars plugin setting.
	SettingKeyProposalNameSupportedChars = "proposalnamesupportedchars"

	// SettingKeyProposalAmountMin is the plugin setting key for
	// the SettingProposalAmountMin plugin setting.
	SettingKeyProposalAmountMin = "proposalamountmin"

	// SettingKeyProposalAmountMax is the plugin setting key for
	// the SettingProposalAmountMax plugin setting.
	SettingKeyProposalAmountMax = "proposalamountmax"

	// SettingKeyProposalStartDateMin is the plugin settings key for
	// the SettingProposalStartDateMin plugin setting.
	SettingKeyProposalStartDateMin = "proposalstartdatemin"

	// SettingKeyProposalEndDateMax is the plugin settings key for
	// the SettingProposalEndDateMax plugin setting.
	SettingKeyProposalEndDateMax = "proposalenddatemax"

	// SettingKeyProposalDomains is the plugin setting key for the
	// SettingProposalDomains plugin setting.
	SettingKeyProposalDomains = "proposaldomains"
)

// Plugin setting default values. These can be overridden by providing a plugin
// setting key and value to the plugin on startup.
const (
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

	// SettingProposalAmountMin is the default minimum funding amount
	// in cents a proposal can have.
	SettingProposalAmountMin uint64 = 100000 // 1k usd in cents.

	// SettingProposalAmountMax is the default maximum funding amount
	// in cents a proposal can have.
	SettingProposalAmountMax uint64 = 100000000 // 1m usd in cents.

	// SettingProposalEndDateMax is the default maximum possible proposal
	// end date - seconds from current time.
	SettingProposalEndDateMax int64 = 31557600 // 365.25 days in seconds.

	// SettingProposalStartDateMin is the default minimum possible proposal
	// start date - seconds from current time.
	SettingProposalStartDateMin int64 = 604800 // One week in seconds.
)

var (
	// SettingProposalNameSupportedChars contains the supported
	// characters in a proposal name.
	SettingProposalNameSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#",
		"/", "(", ")", "!", "?", "\"", "'",
	}

	// SettingProposalDomains contains the default proposal domains.
	SettingProposalDomains = []string{
		"development",
		"marketing",
		"research",
		"design",
	}
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT uint32

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

	// ErrorCodeProposalStartDateInvalid is returned when a proposal start date
	// does not adhere to the proposal start date settings.
	ErrorCodeProposalStartDateInvalid ErrorCodeT = 8

	// ErrorCodeProposalEndDateInvalid is returned when a proposal end date
	// does not adhere to the proposal end date settings.
	ErrorCodeProposalEndDateInvalid ErrorCodeT = 9

	// ErrorCodeProposalAmountInvalid is returned when a proposal amount
	// is not in the range defined by the amount min/max plugin settings.
	ErrorCodeProposalAmountInvalid ErrorCodeT = 10

	// ErrorCodeProposalDomainInvalid is returned when a proposal domain
	// is not one of the supported domains.
	ErrorCodeProposalDomainInvalid ErrorCodeT = 11

	// ErrorCodeTokenInvalid is returned when a record token is
	// provided as part of a plugin command payload and is not a valid
	// token or the payload token does not match the token that was
	// used in the API request.
	ErrorCodeTokenInvalid ErrorCodeT = 12

	// ErrorCodePublicKeyInvalid is returned when a public key is not
	// a valid hex encoded, Ed25519 public key.
	ErrorCodePublicKeyInvalid ErrorCodeT = 13

	// ErrorCodeSignatureInvalid is returned when a signature is not
	// a valid hex encoded, Ed25519 signature or when the signature is
	// wrong.
	ErrorCodeSignatureInvalid ErrorCodeT = 14

	// ErrorCodeBillingStatusAlreadySet is returned when a billing status
	// was already set.
	ErrorCodeBillingStatusAlreadySet = 15

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 16
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                  "error code invalid",
		ErrorCodeTextFileNameInvalid:      "text file name invalid",
		ErrorCodeTextFileSizeInvalid:      "text file size invalid",
		ErrorCodeTextFileMissing:          "text file is misisng",
		ErrorCodeImageFileCountInvalid:    "image file count invalid",
		ErrorCodeImageFileSizeInvalid:     "image file size invalid",
		ErrorCodeProposalNameInvalid:      "proposal name invalid",
		ErrorCodeVoteStatusInvalid:        "vote status invalid",
		ErrorCodeProposalAmountInvalid:    "proposal amount invalid",
		ErrorCodeProposalStartDateInvalid: "proposal start date invalid",
		ErrorCodeProposalEndDateInvalid:   "proposal end date invalid",
		ErrorCodeProposalDomainInvalid:    "proposal domain invalid",
		ErrorCodeTokenInvalid:             "token invalid",
		ErrorCodePublicKeyInvalid:         "public key invalid",
		ErrorCodeSignatureInvalid:         "signature invalid",
		ErrorCodeBillingStatusAlreadySet:  "billing status already set",
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
	Name      string `json:"name"`
	Amount    uint64 `json:"amount"`    // Funding amount in cents
	StartDate int64  `json:"startdate"` // Start date, Unix time
	EndDate   int64  `json:"enddate"`   // Estimated end date, Unix time
	Domain    string `json:"domain"`    // Proposal domain
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
