// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a plugin that extends records with functionality for
// decred's proposal system.
package pi

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "pi"

	// CmdSetBillingStatus command sets the billing status.
	CmdSetBillingStatus = "setbillingstatus"
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

	// SettingKeyTitleLengthMin is the plugin setting key for
	// the SettingTitleLengthMin plugin setting.
	SettingKeyTitleLengthMin = "titlelengthmin"

	// SettingKeyTitleLengthMax is the plugin setting key for
	// the SettingTitleLengthMax plugin setting.
	SettingKeyTitleLengthMax = "titlelengthmax"

	// SettingKeyTitleSupportedChars is the plugin setting key
	// for the SettingTitleSupportedChars plugin setting.
	SettingKeyTitleSupportedChars = "titlesupportedchars"

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

	// SettingTitleLengthMin is the default minimum number of
	// characters that a proposal name or a proposal update title can be.
	SettingTitleLengthMin uint32 = 8

	// SettingTitleLengthMax is the default maximum number of
	// characters that a proposal name or a proposal update title can be.
	SettingTitleLengthMax uint32 = 80

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
	// SettingTitleSupportedChars contains the supported
	// characters in a proposal name or a proposal update title.
	SettingTitleSupportedChars = []string{
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
	// ErrorCodeInvalid represents an invalid error code.
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

	// ErrorCodeTitleInvalid is returned when a title, proposal title or proposal
	// update title, does not adhere to the title regexp requirements.
	ErrorCodeTitleInvalid ErrorCodeT = 6

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

	// ErrorCodeBillingStatusChangeNotAllowed is returned when a billing status
	// change is not allowed.
	ErrorCodeBillingStatusChangeNotAllowed = 15

	// ErrorCodeBillingStatusInvalid is returned when an invalid billing status
	// is provided.
	ErrorCodeBillingStatusInvalid = 16

	// ErrorCodeCommentWriteNotAllowed is returned when a user attempts to submit
	// a new comment or a comment vote, but does not have permission to. This
	// could be because the proposal's vote status does not allow for any
	// additional changes or because the user is trying to write to a thread that
	// is not allowed. Example, once a proposal vote is approved the only comment
	// writes that are allowed are replies and votes to the author's most recent
	// update thread.
	ErrorCodeCommentWriteNotAllowed = 17

	// ErrorCodeExtraDataHintInvalid is returned when the extra data hint is
	// invalid.
	ErrorCodeExtraDataHintInvalid = 18

	// ErrorCodeExtraDataInvalid is returned when the extra data payload is
	// invalid.
	ErrorCodeExtraDataInvalid = 19

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 20
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                       "error code invalid",
		ErrorCodeTextFileNameInvalid:           "text file name invalid",
		ErrorCodeTextFileSizeInvalid:           "text file size invalid",
		ErrorCodeTextFileMissing:               "text file is misisng",
		ErrorCodeImageFileCountInvalid:         "image file count invalid",
		ErrorCodeImageFileSizeInvalid:          "image file size invalid",
		ErrorCodeTitleInvalid:                  "title invalid",
		ErrorCodeVoteStatusInvalid:             "vote status invalid",
		ErrorCodeProposalAmountInvalid:         "proposal amount invalid",
		ErrorCodeProposalStartDateInvalid:      "proposal start date invalid",
		ErrorCodeProposalEndDateInvalid:        "proposal end date invalid",
		ErrorCodeProposalDomainInvalid:         "proposal domain invalid",
		ErrorCodeTokenInvalid:                  "token invalid",
		ErrorCodePublicKeyInvalid:              "public key invalid",
		ErrorCodeSignatureInvalid:              "signature invalid",
		ErrorCodeBillingStatusChangeNotAllowed: "billing status change is not allowed",
		ErrorCodeBillingStatusInvalid:          "billing status invalid",
		ErrorCodeCommentWriteNotAllowed:        "comment write not allowed",
		ErrorCodeExtraDataHintInvalid:          "extra data hint invalid",
		ErrorCodeExtraDataInvalid:              "extra data payload invalid",
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
