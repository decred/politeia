// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/cms/v2"

	// RoutePolicy returns the policy for the cms API.
	RoutePolicy = "/policy"

	// RouteSetInvoiceStatus sets the invoice's status.
	RouteSetInvoiceStatus = "/setinvoicestatus"

	// RouteSummaries returns the invoice summary for a page of
	// records.
	RouteSummaries = "/summaries"

	// RouteInvoiceStatusChanges returns the invoice's status changes.
	RouteInvoiceStatusChanges = "/invoicestatuschanges"
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

type DomainTypeT int

const (
	// Domain types
	DomainTypeInvalid   DomainTypeT = 0 // Invalid Domain type
	DomainTypeDeveloper DomainTypeT = 1 // Developer domain
	DomainTypeMarketing DomainTypeT = 2 // Marketing domain
	DomainTypeResearch  DomainTypeT = 4 // Research domain
	DomainTypeDesign    DomainTypeT = 5 // Design domain
)

var (
	// PolicySupportedCMSDomains supplies the currently available domain types
	// and descriptions of them.
	SupportedDomains = []AvailableDomain{
		{
			Description: "development",
			Type:        DomainTypeDeveloper,
		},
		{
			Description: "marketing",
			Type:        DomainTypeMarketing,
		},
		{
			Description: "research",
			Type:        DomainTypeResearch,
		},
		{
			Description: "design",
			Type:        DomainTypeDesign,
		},
	}
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

var (
	// PolicyCMSSupportedLineItemTypes supplies the currently available invoice types
	// and descriptions of them.
	LineItemTypes = map[LineItemTypeT]string{
		LineItemTypeLabor:    "labor",
		LineItemTypeExpense:  "expense",
		LineItemTypeMisc:     "misc",
		LineItemTypeSubHours: "subhours",
	}
)

type ContractorTypeT int

const (
	ContractorTypeInvalid         ContractorTypeT = 0 // Invalid contractor type
	ContractorTypeDirect          ContractorTypeT = 1 // Direct contractor
	ContractorTypeSupervisor      ContractorTypeT = 2 // Supervisor contractor
	ContractorTypeSubContractor   ContractorTypeT = 3 // SubContractor
	ContractorTypeNominee         ContractorTypeT = 4 // Nominated DCC user
	ContractorTypeRevoked         ContractorTypeT = 5 // Revoked CMS User
	ContractorTypeTemp            ContractorTypeT = 6 // Temporary Contractor (only allowed 1 invoice)
	ContractorTypeTempDeactivated ContractorTypeT = 7 // Temporary Contractor that has been deactivated
	ContractorTypeProposal        ContractorTypeT = 8 // Contractor appproved by proposal, but not DCC
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

// AvailableDomain contains a domain type and it's corresponding description.
type AvailableDomain struct {
	Description string      `json:"description"`
	Type        DomainTypeT `json:"type"`
}

// AvailableLineItemType contains a line item type and it's description
type AvailableLineItemType struct {
	Description string        `json:"description"`
	Type        LineItemTypeT `json:"type"`
}

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

// Policy requests the policy settings for the cms API. It includes the policy
// guidlines for the contents of a invoice record.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
//
type PolicyReply struct {
	PasswordLengthMin          uint32   `json:"passwordlengthmin"`
	UsernameLengthMin          uint32   `json:"usernamelengthmin"`
	UsernameLengthMax          uint32   `json:"usernamelengthmax"`
	TextFileSizeMax            uint32   `json:"textfilesizemax"`
	ImageFileCountMax          uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax           uint32   `json:"imagefilesizemax"`
	MDsCountMax                uint32   `json:"mdscountmax"`
	MDSizeMax                  uint32   `json:"mdssizemax"`
	ValidMIMETypes             []string `json:"validmimetypes"`
	LineItemColLengthMin       uint32   `json:"lineitemcollengthmin"`
	LineItemColLengthMax       uint32   `json:"lineitemcollengthmax"`
	NameLengthMax              uint32   `json:"namelengthmax"`
	NameLengthMin              uint32   `json:"namelengthmin"`
	LocationLengthMax          uint32   `json:"locationlengthmax"`
	LocationLengthMin          uint32   `json:"locationlengthmin"`
	ContactLengthMax           uint32   `json:"contactlengthmax"`
	ContactLengthMin           uint32   `json:"contactlengthmin"`
	StatementLengthMax         uint32   `json:"statementlengthmax"`
	StatementLengthMin         uint32   `json:"statementlengthmin"`
	InvoiceFieldSupportedChars []string `json:"invoicefieldsupportedchars"`
	UsernameSupportedChars     []string `json:"usernamesupportedchars"`
	NameLocationSupportedChars []string `json:"namelocationsupportedchars"`
	ContactSupportedChars      []string `json:"contactsupportedchars"`
	StatementSupportedChars    []string `json:"statementsupportedchars"`
	LineItemTypes              []string `json:"lineitemtypes"`
	Domains                    []string `json:"invoicedomains"`
}

const (
	// FileNameIndexFile is the file name of the invoice markdown
	// file that contains the main invoice contents. All invoice
	// submissions must contain an index file.
	FileNameIndexFile = "index.md"

	// FileNameInvoiceMetadata is the file name of the user submitted
	// InvoiceMetadata. All invoice submissions must contain a
	// invoice metadata file.
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
}

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

type InvoiceStatusT uint32

const (
	// Invoice status codes
	InvoiceStatusInvalid  InvoiceStatusT = 0 // Invalid status
	InvoiceStatusNotFound InvoiceStatusT = 1 // Invoice not found
	InvoiceStatusNew      InvoiceStatusT = 2 // Invoice has not been reviewed
	InvoiceStatusUpdated  InvoiceStatusT = 3 // Invoice has unreviewed changes
	InvoiceStatusDisputed InvoiceStatusT = 4 // Invoice has been disputed for some reason
	InvoiceStatusRejected InvoiceStatusT = 5 // Invoice fully rejected and closed
	InvoiceStatusApproved InvoiceStatusT = 6 // Invoice has been approved
	InvoiceStatusPaid     InvoiceStatusT = 7 // Invoice has been paid
	InvoiceStatusLast     InvoiceStatusT = 8 // Used for unit test
)

var (
	InvoiceStatusTypes = map[InvoiceStatusT]string{
		InvoiceStatusInvalid:  "invalid",
		InvoiceStatusNotFound: "notfound",
		InvoiceStatusNew:      "new",
		InvoiceStatusUpdated:  "updated",
		InvoiceStatusDisputed: "disputed",
		InvoiceStatusRejected: "rejected",
		InvoiceStatusApproved: "approved",
		InvoiceStatusPaid:     "paid",
	}
)

// InvoiceStatusChange represents the structure that is saved to disk when
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
type InvoiceStatusChange struct {
	Token     string         `json:"token"`
	Status    InvoiceStatusT `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	PublicKey string         `json:"publickey"`
	Signature string         `json:"signature"`
	Receipt   string         `json:"receipt"`
	Timestamp int64          `json:"timestamp"` // Unix timestamp
}

// SetInvoiceStatus sets the billing status of a proposal. Some billing status
// changes require a reason to be given. Only admins can update the billing
// status of a proposal.
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
// Status field is the string value of the InvoiceStatusT type which is defined
// along with all of it's possible values in the pi plugin API.
type Summary struct {
	Status string `json:"status"`
}

// InvoiceStatusChanges requests the billing status changes for the provided
// proposal token.
type InvoiceStatusChanges struct {
	Token string `json:"token"`
}

// InvoiceStatusChangesReply is the reply to the InvoiceStatusChanges command.
type InvoiceStatusChangesReply struct {
	InvoiceStatusChanges []InvoiceStatusChange `json:"billingstatuschanges"`
}

// InvoiceExchangeRate contains the request to receive a monthly exchange rate
type InvoiceExchangeRate struct {
	Month uint `json:"month"`
	Year  uint `json:"year"`
}

// InvoiceExchangeRateReply returns the calculated monthly exchange rate
type InvoiceExchangeRateReply struct {
	ExchangeRate uint `json:"exchangerate"` // in USD cents
}
