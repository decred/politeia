// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package cms provides a plugin that extends records with functionality for
// decred's invoice system.
package cms

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "cms"

	// CmdSetInvoiceStatus command sets the invoice status.
	CmdSetInvoiceStatus = "setinvoicestatus"

	// CmdSummary command returns a summary for a invoice.
	CmdSummary = "summary"

	// CmdInvoiceStatusChanges command returns the invoice status changes
	// of a invoice.
	CmdInvoiceStatusChanges = "invoicestatuschanges"
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

	// SettingKeyInvoiceDomains is the plugin setting key for the
	// SettingInvoiceDomains plugin setting.
	SettingKeyInvoiceDomains = "invoicedomains"

	// SettingKeyPasswordLengthMin is the plugin setting key for the
	// SettingKeyPasswordLengthMin plugin setting.
	SettingKeyPasswordLengthMin = "passwordlengthmin"

	// SettingKeyUsernameLengthMin is the plugin setting key for the
	// SettingKeyUsernameLengthMin plugin setting.
	SettingKeyUsernameLengthMin = "usernamelengthmin"

	// SettingKeyUsernameLengthMax is the plugin setting key for the
	// SettingKeyUsernameLengthMax plugin setting.
	SettingKeyUsernameLengthMax = "usernamelengthmax"

	// SettingKeyMDsCountMax is the plugin setting key for the
	// SettingKeyMDsCountMax plugin setting.
	SettingKeyMDsCountMax = "mdscountmax"

	// SettingKeyMDSizeMax is the plugin setting key for the
	// SettingKeyMDSizeMax plugin setting.
	SettingKeyMDsSizeMax = "mdssizemax"

	// SettingKeyValidMIMETypes is the plugin setting key for the
	// SettingKeyValidMIMETypes plugin setting.
	SettingKeyValidMIMETypes = "validmimetypes"

	// SettingKeyLineItemColLengthMin is the plugin setting key for the
	// SettingKeyLineItemColLengthMin plugin setting.
	SettingKeyLineItemColLengthMin = "lineitemcollengthmin"

	// SettingKeyLineItemColLengthMax is the plugin setting key for the
	// SettingKeyLineItemColLengthMax plugin setting.
	SettingKeyLineItemColLengthMax = "lineitemcollengthmax"

	// SettingKeyNameLengthMax is the plugin setting key for the
	// SettingKeyNameLengthMax plugin setting.
	SettingKeyNameLengthMax = "namelengthmax"

	// SettingKeyNameLengthMin is the plugin setting key for the
	// SettingKeyNameLengthMin plugin setting.
	SettingKeyNameLengthMin = "namelengthmin"

	// SettingKeyLocationLengthMax is the plugin setting key for the
	// SettingKeyLocationLengthMax plugin setting.
	SettingKeyLocationLengthMax = "locationlengthmax"

	// SettingKeyLocationLengthMin is the plugin setting key for the
	// SettingKeyLocationLengthMin plugin setting.
	SettingKeyLocationLengthMin = "locationlengthmin"

	// SettingKeyContactLengthMax is the plugin setting key for the
	// SettingKeyContactLengthMax plugin setting.
	SettingKeyContactLengthMax = "contactlengthmax"

	// SettingKeyContactLengthMin is the plugin setting key for the
	// SettingKeyContactLengthMin plugin setting.
	SettingKeyContactLengthMin = "contactlengthmin"

	// SettingKeyStatementLengthMin is the plugin setting key for the
	// SettingKeyStatementLengthMin plugin setting.
	SettingKeyStatementLengthMin = "statementlengthmin"

	// SettingKeyStatementLengthMax is the plugin setting key for the
	// SettingKeyStatementLengthMax plugin setting.
	SettingKeyStatementLengthMax = "statementlengthmax"

	// SettingKeyContractorRateMin is the plugin setting key for the
	// SettingKeyContractorRateMin plugin setting.
	SettingKeyContractorRateMin = "contractorratemin"

	// SettingKeyContractorRateMax is the plugin setting key for the
	// SettingKeyContractorRateMax plugin setting.
	SettingKeyContractorRateMax = "contractorratemax"

	// SettingKeyInvoiceFieldSupportedChars is the plugin setting key for the
	// SettingKeyInvoiceFieldSupportedChars plugin setting.
	SettingKeyInvoiceFieldSupportedChars = "invoicefieldsupportedchars"

	// SettingKeyNameLocationSupportedChars is the plugin setting key for the
	// SettingKeyNameLocationSupportedChars plugin setting.
	SettingKeyNameLocationSupportedChars = "namelocationsupportedchars"

	// SettingKeyContactSupportedChars is the plugin setting key for the
	// SettingKeyContactSupportedChars plugin setting.
	SettingKeyContactSupportedChars = "contactsupportedchars"

	// SettingKeyStatementSupportedChars is the plugin setting key for the
	// SettingKeyStatementSupportedChars plugin setting.
	SettingKeyStatementSupportedChars = "statementsupportedchars"

	// SettingKeyLineItemTypes is the plugin setting key for the
	// SettingKeyLineItemTypes plugin setting.
	SettingKeyLineItemTypes = "lineitemtypes"
)

// Plugin setting default values. These can be overridden by providing a plugin
// setting key and value to the plugin on startup.
const (
	// SettingTextFileSizeMax is the default maximum allowed size of a
	// text file in bytes.
	SettingTextFileSizeMax uint32 = 512 * 1024

	// SettingImageFileCountMax is the default maximum number of image
	// files that can be included in a invoice.
	SettingImageFileCountMax uint32 = 5

	// SettingImageFileSizeMax is the default maximum allowed size of
	// an image file in bytes.
	SettingImageFileSizeMax uint32 = 512 * 1024

	// SettingPasswordLengthMin is the default minimum number of
	// characters that a password can be.
	SettingPasswordLengthMin uint32 = 3

	// SettingUsernameLengthMin is the default minimum number of
	// characters that a username can be.
	SettingUsernameLengthMin uint32 = 3

	// SettingUsernameLengthMax is the default maximum number of
	// characters that a username can be.
	SettingUsernameLengthMax uint32 = 50

	// SettingTitleLengthMin is the default minimum number of
	// characters that a invoice name or a invoice update title can be.
	SettingTitleLengthMin uint32 = 8

	// SettingTitleLengthMax is the default maximum number of
	// characters that a invoice name or a invoice update title can be.
	SettingTitleLengthMax uint32 = 80

	// SettingMdsCountMax is the maximum number of markdown files accepted
	// when creating a new invoice
	SettingMdsCountMax uint32 = 1

	// SettingMDSize is the maximum markdown file size (in bytes)
	// accepted when creating a new invoice
	SettingMDSizeMax uint32 = 512 * 1024

	// SettingNameLength is the max length of a contractor name
	SettingNameLengthMax uint32 = 50

	// SettingNameLength is the min length of a contractor name
	SettingNameLengthMin uint32 = 3

	// SettingLocationLength is the max length of a contractor location
	SettingLocationLengthMax uint32 = 100

	// SettingLocationLength is the min length of a contractor location
	SettingLocationLengthMin uint32 = 3

	// SettingContactLength is the max length of a contractor contact
	SettingContactLengthMax uint32 = 100

	// SettingContactLength is the min length of a contractor contact
	SettingContactLengthMin uint32 = 3

	// SettingLineItemColLength is the minimun length for the strings in
	// each column field of the lineItem structure.
	SettingLineItemColLengthMin uint32 = 3

	// SettingLineItemColLength is the maximum length for the strings in
	// each column field of the lineItem structure.
	SettingLineItemColLengthMax uint32 = 500

	// SettingSponsorStatementLength is the minimum length for the sponsor
	// statement contained within a DCC
	SettingSponsorStatementLengthMin uint32 = 0

	// SettingSponsorStatementLength is the maximum length for the sponsor
	// statement contained within a DCC
	SettingSponsorStatementLengthMax uint32 = 5000

	// SettingContractorRateMin is the default minimum amount a contractor's
	// rate (in USD cents)
	SettingContractorRateMin uint32 = 500

	// SettingContractorRateMax is the default maximum amount a contractor's
	// rate (in USD cents)
	SettingContractorRateMax uint32 = 50000
)

var (

	// SettingValidMIMETypes is the accepted mime types of attachments
	// in invoices
	SettingValidMIMETypes = []string{
		"image/png",
	}

	// SettingInvoiceFieldSupportedChars is the regular expression of a valid
	// invoice fields.
	SettingInvoiceFieldSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'"}

	// SettingNameLocationSupportedChars is the regular expression of a valid
	// name or location for registering users on cms.
	SettingNameLocationSupportedChars = []string{
		"A-z", "0-9", ".", "-", " ", ","}

	// SettingContactSupportedChars is the regular expression of a valid
	// contact for registering users on cms.
	SettingContactSupportedChars = []string{
		"A-z", "0-9", "&", ".", ":", "-", "_", "@", "+", ",", " "}

	// SettingSponsorStatementSupportedChars is the regular expression of a valid
	// sponsor statement for DCC in cms.
	SettingSponsorStatementSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'", "\n"}

	// SettingInvoiceDomains contains the default invoice domains.
	SettingInvoiceDomains = []string{
		"development",
		"marketing",
		"research",
		"design",
	}

	SettingLineItemTypes = []string{
		"labor",
		"expense",
		"misc",
		"subhours",
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

	// ErrorCodeTextFileMissing is returned when the invoice does not
	// contain one or more of the required text files.
	ErrorCodeTextFileMissing ErrorCodeT = 3

	// ErrorCodeImageFileCountInvalid is returned when the number of
	// image attachments exceedes the ImageFileCountMax setting.
	ErrorCodeImageFileCountInvalid ErrorCodeT = 4

	// ErrorCodeImageFileSizeInvalid is returned when an image file
	// size exceedes the ImageFileSizeMax setting.
	ErrorCodeImageFileSizeInvalid ErrorCodeT = 5

	// ErrorCodeTitleInvalid is returned when a title, invoice title or invoice
	// update title, does not adhere to the title regexp requirements.
	ErrorCodeTitleInvalid ErrorCodeT = 6

	// ErrorCodeInvoiceDomainInvalid is returned when a invoice domain
	// is not one of the supported domains.
	ErrorCodeInvoiceDomainInvalid ErrorCodeT = 7

	// ErrorCodeTokenInvalid is returned when a record token is
	// provided as part of a plugin command payload and is not a valid
	// token or the payload token does not match the token that was
	// used in the API request.
	ErrorCodeTokenInvalid ErrorCodeT = 8

	// ErrorCodePublicKeyInvalid is returned when a public key is not
	// a valid hex encoded, Ed25519 public key.
	ErrorCodePublicKeyInvalid ErrorCodeT = 9

	// ErrorCodeSignatureInvalid is returned when a signature is not
	// a valid hex encoded, Ed25519 signature or when the signature is
	// wrong.
	ErrorCodeSignatureInvalid ErrorCodeT = 10

	// ErrorCodeInvoiceStatusChangeNotAllowed is returned when a invoice status
	// change is not allowed.
	ErrorCodeInvoiceStatusChangeNotAllowed = 11

	// ErrorCodeInvoiceStatusInvalid is returned when an invalid invoice status
	// is provided.
	ErrorCodeInvoiceStatusInvalid = 12

	// ErrorCodeCommentWriteNotAllowed is returned when a user attempts to submit
	// a new comment or a comment vote, but does not have permission to. This
	// could be because the invoice's status does not allow for any
	// additional changes.
	ErrorCodeCommentWriteNotAllowed = 13

	// ErrorCodeExtraDataHintInvalid is returned when the extra data hint is
	// invalid.
	ErrorCodeExtraDataHintInvalid = 14

	// ErrorCodeExtraDataInvalid is returned when the extra data payload is
	// invalid.
	ErrorCodeExtraDataInvalid = 15

	// Legacy CMS
	ErrorStatusMalformedName                  = 16
	ErrorStatusMalformedLocation              = 17
	ErrorStatusInvoiceNotFound                = 18
	ErrorStatusInvalidMonthYearRequest        = 19
	ErrorStatusMalformedInvoiceFile           = 20
	ErrorStatusInvalidInvoiceStatusTransition = 21
	ErrorStatusReasonNotProvided              = 22
	ErrorStatusInvoiceDuplicate               = 23
	ErrorStatusInvalidPaymentAddress          = 24
	ErrorStatusMalformedLineItem              = 25
	ErrorStatusInvoiceMissingName             = 26
	ErrorStatusInvoiceMissingContact          = 27
	ErrorStatusInvoiceMissingRate             = 28
	ErrorStatusInvoiceInvalidRate             = 29
	ErrorStatusInvoiceMalformedContact        = 30
	ErrorStatusMalformedProposalToken         = 31
	ErrorStatusMalformedDomain                = 32
	ErrorStatusMalformedSubdomain             = 33
	ErrorStatusMalformedDescription           = 34
	ErrorStatusWrongInvoiceStatus             = 35
	ErrorStatusInvoiceRequireLineItems        = 36
	ErrorStatusInvalidInvoiceMonthYear        = 37
	ErrorStatusInvalidExchangeRate            = 38
	ErrorStatusInvalidLineItemType            = 39
	ErrorStatusInvalidLaborExpense            = 40
	ErrorStatusDuplicatePaymentAddress        = 41
	ErrorStatusInvalidDatesRequested          = 42
	ErrorStatusInvalidInvoiceEditMonthYear    = 43
	ErrorStatusInvalidDCCType                 = 44
	ErrorStatusInvalidNominatingDomain        = 45
	ErrorStatusMalformedSponsorStatement      = 46
	ErrorStatusMalformedDCCFile               = 47
	ErrorStatusInvalidDCCComment              = 48
	ErrorStatusInvalidDCCStatusTransition     = 49
	ErrorStatusDuplicateEmail                 = 50
	ErrorStatusInvalidUserNewInvoice          = 51
	ErrorStatusInvalidDCCNominee              = 52
	ErrorStatusDCCNotFound                    = 53
	ErrorStatusWrongDCCStatus                 = 54
	ErrorStatusInvalidSupportOppose           = 55
	ErrorStatusDuplicateSupportOppose         = 56
	ErrorStatusUserIsAuthor                   = 57
	ErrorStatusInvalidUserDCC                 = 58
	ErrorStatusInvalidDCCContractorType       = 59
	ErrorStatusInvalidTypeSubHoursLineItem    = 60
	ErrorStatusMissingSubUserIDLineItem       = 61
	ErrorStatusInvalidSubUserIDLineItem       = 62
	ErrorStatusInvalidSupervisorUser          = 63
	ErrorStatusMalformedDCC                   = 64
	ErrorStatusInvalidDCCVoteStatus           = 65
	ErrorStatusInvalidDCCAllVoteUserWeight    = 66
	ErrorStatusDCCVoteEnded                   = 67
	ErrorStatusDCCVoteStillLive               = 68
	ErrorStatusDCCDuplicateVote               = 69
	ErrorStatusMissingCodeStatsUsername       = 70
	ErrorStatusTrackerNotStarted              = 71

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 72
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
		ErrorCodeInvoiceDomainInvalid:          "invoice domain invalid",
		ErrorCodeTokenInvalid:                  "token invalid",
		ErrorCodePublicKeyInvalid:              "public key invalid",
		ErrorCodeSignatureInvalid:              "signature invalid",
		ErrorCodeInvoiceStatusChangeNotAllowed: "invoice status change is not allowed",
		ErrorCodeInvoiceStatusInvalid:          "invoice status invalid",
		ErrorCodeCommentWriteNotAllowed:        "comment write not allowed",
		ErrorCodeExtraDataHintInvalid:          "extra data hint invalid",
		ErrorCodeExtraDataInvalid:              "extra data payload invalid",
		// Legacy CMS
		ErrorStatusMalformedName:                  "malformed name",
		ErrorStatusMalformedLocation:              "malformed location",
		ErrorStatusInvoiceNotFound:                "invoice cannot be found",
		ErrorStatusInvalidMonthYearRequest:        "month or year was set, while the other was not",
		ErrorStatusInvalidInvoiceStatusTransition: "invalid invoice status transition",
		ErrorStatusReasonNotProvided:              "reason for action not provided",
		ErrorStatusMalformedInvoiceFile:           "submitted invoice file is malformed",
		ErrorStatusInvoiceDuplicate:               "submitted invoice is a duplicate of an existing invoice",
		ErrorStatusInvalidPaymentAddress:          "invalid payment address",
		ErrorStatusMalformedLineItem:              "malformed line item submitted",
		ErrorStatusInvoiceMissingName:             "invoice missing contractor name",
		ErrorStatusInvoiceMissingContact:          "invoice missing contractor contact",
		ErrorStatusInvoiceMalformedContact:        "invoice has malformed contractor contact",
		ErrorStatusInvoiceMissingRate:             "invoice missing contractor rate",
		ErrorStatusInvoiceInvalidRate:             "invoice has invalid contractor rate",
		ErrorStatusMalformedProposalToken:         "line item has malformed proposal token",
		ErrorStatusMalformedDomain:                "line item has malformed domain",
		ErrorStatusMalformedSubdomain:             "line item has malformed subdomain",
		ErrorStatusMalformedDescription:           "line item has malformed description",
		ErrorStatusWrongInvoiceStatus:             "invoice is an wrong status to be editted (approved, rejected or paid)",
		ErrorStatusInvoiceRequireLineItems:        "invoices require at least 1 line item",
		ErrorStatusInvalidInvoiceMonthYear:        "an invalid month/year was submitted on an invoice",
		ErrorStatusInvalidExchangeRate:            "exchange rate was invalid or didn't match expected result",
		ErrorStatusInvalidLineItemType:            "line item has an invalid type",
		ErrorStatusInvalidLaborExpense:            "line item has an invalid labor or expense field",
		ErrorStatusDuplicatePaymentAddress:        "a duplicate payment address was used",
		ErrorStatusInvalidDatesRequested:          "invalid dates were requested",
		ErrorStatusInvalidInvoiceEditMonthYear:    "invalid attempt to edit invoice month/year",
		ErrorStatusInvalidDCCType:                 "invalid DCC type was included",
		ErrorStatusInvalidNominatingDomain:        "non-matching domain was attempt",
		ErrorStatusMalformedSponsorStatement:      "DCC sponsor statement was malformed",
		ErrorStatusMalformedDCCFile:               "submitted DCC file was malformed according to standards",
		ErrorStatusInvalidDCCComment:              "submitted DCC comment must either be aye or nay",
		ErrorStatusInvalidDCCStatusTransition:     "invalid status transition for a DCC",
		ErrorStatusDuplicateEmail:                 "another user already has that email registered",
		ErrorStatusInvalidUserNewInvoice:          "current contractor status does not allow new invoices to be created",
		ErrorStatusInvalidDCCNominee:              "invalid nominee user was submitted for a DCC",
		ErrorStatusDCCNotFound:                    "a requested dcc was not found",
		ErrorStatusWrongDCCStatus:                 "cannot comment/approve/oppose DCC if it's not active state",
		ErrorStatusInvalidSupportOppose:           "invalid support or opposition vote was included in the request, must be aye or nay",
		ErrorStatusDuplicateSupportOppose:         "user has already supported or opposed the given DCC",
		ErrorStatusUserIsAuthor:                   "user cannot support or oppose their own sponsored DCC",
		ErrorStatusInvalidUserDCC:                 "user is not authorized to complete the DCC request",
		ErrorStatusInvalidDCCContractorType:       "DCC must have a valid contractor type",
		ErrorStatusInvalidTypeSubHoursLineItem:    "must be a Supervisor Contractor to submit a subcontractor hours line item",
		ErrorStatusMissingSubUserIDLineItem:       "must supply a userid for a subcontractor hours line item",
		ErrorStatusInvalidSubUserIDLineItem:       "the userid supplied for the subcontractor hours line item is invalid",
		ErrorStatusInvalidSupervisorUser:          "attempted input of an invalid supervisor user id",
		ErrorStatusMalformedDCC:                   "malformed dcc detected",
		ErrorStatusInvalidDCCVoteStatus:           "the DCC to be voted isn't currently up for an all user vote",
		ErrorStatusInvalidDCCAllVoteUserWeight:    "the user does not have a corresponding user weight for this vote",
		ErrorStatusDCCVoteEnded:                   "the all contractor voting period has ended",
		ErrorStatusDCCVoteStillLive:               "cannot update status of a DCC while a vote is still live",
		ErrorStatusDCCDuplicateVote:               "user has already submitted a vote for the given dcc",
		ErrorStatusMissingCodeStatsUsername:       "codestats site username is required to receive code stats",
		ErrorStatusTrackerNotStarted:              "code tracker required for attempted request, check token setting in config",
	}
)

const (
	// FileNameIndexFile is the file name of the invoice markdown
	// file. Every invoice is required to have an index file. The
	// index file should contain the invoice content.
	FileNameIndexFile = "index.md"

	// FileNameInvoiceMetadata is the filename of the InvoiceMetadata
	// file that is saved to politeiad. InvoiceMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameInvoiceMetadata = "invoicemetadata.json"
)

// InvoiceMetadata contains metadata that is provided by the user as part of
// the invoice submission bundle. The invoice metadata is included in the
// invoice signature since it is user specified data. The InvoiceMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
type InvoiceMetadata struct {
	Version            uint   `json:"version"` // Version of the invoice input
	Name               string `json:"name"`
	Month              uint   `json:"month"`              // Month of Invoice
	Year               uint   `json:"year"`               // Year of Invoice
	ExchangeRate       uint   `json:"exchangerate"`       // Exchange rate of a given month/year in USD cents
	ContractorName     string `json:"contractorname"`     // IRL name of contractor
	ContractorLocation string `json:"contractorlocation"` // IRL location of contractor
	ContractorContact  string `json:"contractorcontact"`  // Contractor email or other contact
	ContractorRate     uint   `json:"contractorrate"`     // Contractor Pay Rate in USD cents
	PaymentAddress     string `json:"paymentaddress"`     //  DCR payment address
	Domain             string `json:"domain"`             // Invoice domain
}

// InvoiceStatusT represents the invoice status of a invoice that has been
// approved by the Decred stakeholders.
type InvoiceStatusT string

const (
	// InvoiceStatusInvalid is an invalid invoice status.
	InvoiceStatusInvalid  InvoiceStatusT = "invalid"
	InvoiceStatusNotFound InvoiceStatusT = "not found" // Invoice not found
	InvoiceStatusNew      InvoiceStatusT = "new"       // Invoice has not been reviewed
	InvoiceStatusUpdated  InvoiceStatusT = "updated"   // Invoice has unreviewed changes
	InvoiceStatusDisputed InvoiceStatusT = "disputed"  // Invoice has been disputed for some reason
	InvoiceStatusRejected InvoiceStatusT = "rejected"  // Invoice fully rejected and closed
	InvoiceStatusApproved InvoiceStatusT = "approved"  // Invoice has been approved
	InvoiceStatusPaid     InvoiceStatusT = "paid"      // Invoice has been paid
)

type LineItemTypeT int

const (
	// Line item types
	LineItemTypeInvalid  LineItemTypeT = 0 // Invalid type
	LineItemTypeLabor    LineItemTypeT = 1 // Labor line items
	LineItemTypeExpense  LineItemTypeT = 2 // Expenses incurred line items
	LineItemTypeMisc     LineItemTypeT = 3 // Catch all for anything else
	LineItemTypeSubHours LineItemTypeT = 4 // Line items for subcontractor billing
)

// InvoiceInput is the expected structure of the invoice.json file being added to InvoiceRecords.
// Users' raw csv will be inputted and parsed to help in their creation.
type InvoiceInput struct {
	LineItems []LineItemsInput `json:"lineitems"`
}

// LineItemsInput is the expected struct of line items contained within an users'
// invoice input.
type LineItemsInput struct {
	Type          LineItemTypeT `json:"type"`          // Type of work performed
	Domain        string        `json:"domain"`        // Domain of work performed
	Subdomain     string        `json:"subdomain"`     // Subdomain of work performed
	Description   string        `json:"description"`   // Description of work performed
	ProposalToken string        `json:"proposaltoken"` // Link to politeia proposal that work is associated with
	SubUserID     string        `json:"subuserid"`     // UserID of the associated Subcontractor
	SubRate       uint          `json:"subrate"`       // The payrate of the subcontractor
	Labor         uint          `json:"labor"`         // Number of minutes (if labor)
	Expenses      uint          `json:"expenses"`      // Total cost (in USD cents) of line item (if expense or misc)
}

// InvoiceStatusChange represents the structure that is saved to disk when
// a invoice has its invoice status updated. Some invoice status changes
// require a reason to be given. Only admins can update the invoice status
// of a invoice.
//
// PublicKey is the admin public key that can be used to verify the signature.
//
// Signature is the admin signature of the Token+Status+Reason.
//
// Receipt is the server signature of the admin signature.
//
// The PublicKey, Signature, and Receipt are all hex encoded and use the
// ed25519 signature scheme.
type InvoiceStatusChange struct {
	Token     string         `json:"token"`
	Status    InvoiceStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
	Receipt   string         `json:"receipt"`
	Timestamp int64          `json:"timestamp"` // Unix timestamp
}

// SetInvoiceStatus sets the invoice status of a invoice. Some invoice status
// changes require a reason to be given. Only admins can update the invoice
// status of a invoice.
//
// PublicKey is the admin public key that can be used to verify the signature.
//
// Signature is the admin signature of the Token+Status+Reason.
//
// The PublicKey and Signature are hex encoded and use the ed25519 signature
// scheme.
type SetInvoiceStatus struct {
	Token     string         `json:"token"`
	Status    InvoiceStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
}

// SetInvoiceStatusReply is the reply to the SetInvoiceStatus command.
//
// Receipt is the server signature of the client signature. It is hex encoded
// and uses the ed25519 signature scheme.
type SetInvoiceStatusReply struct {
	Receipt   string `json:"receipt"`
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

// Summary requests the summary of a invoice.
type Summary struct {
	Token string `json:"token"`
}

// SummaryReply is the reply to the Summary command.
type SummaryReply struct {
	Summary InvoiceSummary `json:"summary"`
}

// InvoiceSummary summarizes invoice information.
type InvoiceSummary struct {
	Status InvoiceStatusT `json:"status"`
}

const (
	// InvoiceUpdateHint is the hint that is included in a comment's
	// ExtraDataHint field to indicate that the comment is an update
	// from the invoice author.
	InvoiceUpdateHint = "invoiceupdate"
)

// InvoiceUpdateMetadata contains the metadata that is attached to a comment
// in the comment's ExtraData field to indicate that the comment is an update
// from the invoice author.
type InvoiceUpdateMetadata struct {
	Title string `json:"title"`
}

// InvoiceStatusChanges requests the invoice status changes for the provided
// invoice token.
type InvoiceStatusChanges struct {
	Token string `json:"token"`
}

// InvoiceStatusChangesReply is the reply to the InvoiceStatusChanges command.
type InvoiceStatusChangesReply struct {
	InvoiceStatusChanges []InvoiceStatusChange `json:"invoicestatuschanges"`
}
