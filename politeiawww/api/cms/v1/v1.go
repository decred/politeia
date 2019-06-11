package v1

import (
	"github.com/decred/dcrd/dcrutil"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

type ErrorStatusT int
type InvoiceStatusT int
type LineItemTypeT int
type PaymentStatusT int
type DomainTypeT int
type ContractorTypeT int
type DCCTypeT int
type DCCStatusT int

const (

	// Contractor Management Routes
	RouteInviteNewUser       = "/invite"
	RouteRegisterUser        = "/register"
	RouteNewInvoice          = "/invoices/new"
	RouteEditInvoice         = "/invoices/edit"
	RouteInvoiceDetails      = "/invoices/{token:[A-z0-9]{64}}"
	RouteSetInvoiceStatus    = "/invoices/{token:[A-z0-9]{64}}/status"
	RouteUserInvoices        = "/user/invoices"
	RouteNewDCC              = "/dcc/new"
	RouteNewDCCUser          = "/dcc/newuser"
	RouteDCCDetails          = "/dcc/{token:[A-z0-9]{64}}"
	RouteGetDCCs             = "/dcc/status"
	RouteAdminInvoices       = "/admin/invoices"
	RouteAdminUserInvoices   = "/admin/userinvoices"
	RouteGeneratePayouts     = "/admin/generatepayouts"
	RouteLineItemPayouts     = "/admin/lineitempayouts"
	RoutePayInvoices         = "/admin/payinvoices"
	RouteInvoiceComments     = "/invoices/{token:[A-z0-9]{64}}/comments"
	RouteInvoiceExchangeRate = "/invoices/exchangerate"

	// Invoice status codes
	InvoiceStatusInvalid  InvoiceStatusT = 0 // Invalid status
	InvoiceStatusNotFound InvoiceStatusT = 1 // Invoice not found
	InvoiceStatusNew      InvoiceStatusT = 2 // Invoice has not been reviewed
	InvoiceStatusUpdated  InvoiceStatusT = 3 // Invoice has unreviewed changes
	InvoiceStatusDisputed InvoiceStatusT = 4 // Invoice has been disputed for some reason
	InvoiceStatusRejected InvoiceStatusT = 5 // Invoice fully rejected and closed
	InvoiceStatusApproved InvoiceStatusT = 6 // Invoice has been approved
	InvoiceStatusPaid     InvoiceStatusT = 7 // Invoice has been paid

	// Line item types
	LineItemTypeInvalid LineItemTypeT = 0 // Invalid type
	LineItemTypeLabor   LineItemTypeT = 1 // Labor line items
	LineItemTypeExpense LineItemTypeT = 2 // Expenses incurred line items
	LineItemTypeMisc    LineItemTypeT = 3 // Catch all for anything else

	// Domain types
	DomainTypeInvalid       DomainTypeT = 0 // Invalid Domain type
	DomainTypeDeveloper     DomainTypeT = 1 // Developer domain
	DomainTypeMarketing     DomainTypeT = 2 // Marketing domain
	DomainTypeCommunity     DomainTypeT = 3 // Community domain
	DomainTypeResearch      DomainTypeT = 4 // Research domain
	DomainTypeDesign        DomainTypeT = 5 // Design domain
	DomainTypeDocumentation DomainTypeT = 6 // Documentation domain

	// Contractor types
	ContractorTypeInvalid       ContractorTypeT = 0 // Invalid contractor type
	ContractorTypeDirect        ContractorTypeT = 1 // Direct contractor
	ContractorTypeSupervisor    ContractorTypeT = 2 // Supervisor contractor
	ContractorTypeSubContractor ContractorTypeT = 3 // SubContractor
	ContractorTypeRevoked       ContractorTypeT = 4 // Contractors that have been revoked via DCC
	ContractorTypeDormant       ContractorTypeT = 5 // Contractors that have left for a period of time without invoice or contact
	ContractorTypeNominee       ContractorTypeT = 6 // Nominated DCC user

	// Payment information status types
	PaymentStatusInvalid  PaymentStatusT = 0 // Invalid status
	PaymentStatusWatching PaymentStatusT = 1 // Payment currently watching
	PaymentStatusPaid     PaymentStatusT = 2 // Payment fully paid

	// DCC types
	DCCTypeInvalid    DCCTypeT = 0 // Invalid DCC type
	DCCTypeIssuance   DCCTypeT = 1 // Issuance DCC type
	DCCTypeRevocation DCCTypeT = 2 // Revocation DCC type

	// DCC status types
	DCCStatusInvalid   DCCStatusT = 0 // Invalid issuance/revocation status
	DCCStatusActive    DCCStatusT = 1 // Currently active issuance/revocation (awaiting sponsors)
	DCCStatusSupported DCCStatusT = 2 // Fully supported issuance/revocation (received enough sponsors to proceed)
	DCCStatusApproved  DCCStatusT = 3 // Approved issuance/revocation
	DCCStatusRejected  DCCStatusT = 4 // Rejected issuance/revocation?  In the event of a Debate this would be result of a rejected issuance/revocation (that would override the mere sponsoring).
	DCCStatusDebate    DCCStatusT = 5 // If a issuance/revocation receives enough comments, it would enter a "debate" status that would require a full contractor vote (to be added later).

	InvoiceInputVersion = 1

	// PolicyMaxImages is the maximum number of images accepted
	// when creating a new invoice
	PolicyMaxImages = 5

	// PolicyMaxImageSize is the maximum image file size (in bytes)
	// accepted when creating a new invoice
	PolicyMaxImageSize = 512 * 1024

	// PolicyMaxMDs is the maximum number of markdown files accepted
	// when creating a new invoice
	PolicyMaxMDs = 1

	// PolicyMaxMDSize is the maximum markdown file size (in bytes)
	// accepted when creating a new invoice
	PolicyMaxMDSize = 512 * 1024

	// PolicyMaxNameLength is the max length of a contractor name
	PolicyMaxNameLength = 50

	// PolicyMinNameLength is the min length of a contractor name
	PolicyMinNameLength = 3

	// PolicyMaxLocationLength is the max length of a contractor location
	PolicyMaxLocationLength = 100

	// PolicyMinLocationLength is the min length of a contractor location
	PolicyMinLocationLength = 3

	// PolicyMaxContactLength is the max length of a contractor contact
	PolicyMaxContactLength = 100

	// PolicyMinContactLength is the min length of a contractor contact
	PolicyMinContactLength = 3

	// PolicyInvoiceCommentChar is the character which, when used as the first
	// character of a line, denotes that entire line as a comment.
	PolicyInvoiceCommentChar rune = '#'

	// PolicyInvoiceFieldDelimiterChar is the character that delimits field
	// values for each line item in the CSV.
	PolicyInvoiceFieldDelimiterChar rune = ','

	// PolicyInvoiceLineItemCount is the number of expected fields in the raw
	// csv line items
	PolicyInvoiceLineItemCount = 7

	// PolicyMinLineItemColLength is the minimun length for the strings in
	// each column field of the lineItem structure.
	PolicyMinLineItemColLength = 3

	// PolicyMaxLineItemColLength is the maximum length for the strings in
	// each column field of the lineItem structure.
	PolicyMaxLineItemColLength = 500

	// PolicyMinSponsorStatementLength is the maximum length for the sponsor
	// statement contained within a DCC
	PolicyMinSponsorStatementLength = 0

	// PolicyMaxSponsorStatementLength is the maximum length for the sponsor
	// statement contained within a DCC
	PolicyMaxSponsorStatementLength = 500

	ErrorStatusMalformedName                  www.ErrorStatusT = 1001
	ErrorStatusMalformedLocation              www.ErrorStatusT = 1002
	ErrorStatusInvoiceNotFound                www.ErrorStatusT = 1003
	ErrorStatusInvalidMonthYearRequest        www.ErrorStatusT = 1004
	ErrorStatusMalformedInvoiceFile           www.ErrorStatusT = 1005
	ErrorStatusInvalidInvoiceStatusTransition www.ErrorStatusT = 1006
	ErrorStatusReasonNotProvided              www.ErrorStatusT = 1007
	ErrorStatusInvoiceDuplicate               www.ErrorStatusT = 1008
	ErrorStatusInvalidPaymentAddress          www.ErrorStatusT = 1009
	ErrorStatusMalformedLineItem              www.ErrorStatusT = 1010
	ErrorStatusInvoiceMissingName             www.ErrorStatusT = 1011
	ErrorStatusInvoiceMissingLocation         www.ErrorStatusT = 1012
	ErrorStatusInvoiceMissingContact          www.ErrorStatusT = 1013
	ErrorStatusInvoiceMissingRate             www.ErrorStatusT = 1014
	ErrorStatusInvoiceInvalidRate             www.ErrorStatusT = 1015
	ErrorStatusInvoiceMalformedContact        www.ErrorStatusT = 1016
	ErrorStatusMalformedProposalToken         www.ErrorStatusT = 1017
	ErrorStatusMalformedDomain                www.ErrorStatusT = 1018
	ErrorStatusMalformedSubdomain             www.ErrorStatusT = 1019
	ErrorStatusMalformedDescription           www.ErrorStatusT = 1020
	ErrorStatusWrongInvoiceStatus             www.ErrorStatusT = 1021
	ErrorStatusInvoiceRequireLineItems        www.ErrorStatusT = 1022
	ErrorStatusInvalidInvoiceMonthYear        www.ErrorStatusT = 1024
	ErrorStatusInvalidExchangeRate            www.ErrorStatusT = 1025
	ErrorStatusInvalidLineItemType            www.ErrorStatusT = 1026
	ErrorStatusInvalidLaborExpense            www.ErrorStatusT = 1027
	ErrorStatusDuplicatePaymentAddress        www.ErrorStatusT = 1028
	ErrorStatusInvalidDatesRequested          www.ErrorStatusT = 1029
	ErrorStatusInvalidInvoiceEditMonthYear    www.ErrorStatusT = 1030
	ErrorStatusInvalidDCCType                 www.ErrorStatusT = 1031
	ErrorStatusInvalidNominatingDomain        www.ErrorStatusT = 1032
	ErrorStatusMalformedSponsorStatement      www.ErrorStatusT = 1033
	ErrorStatusMalformedDCCFile               www.ErrorStatusT = 1034
	ErrorStatusInvalidDCCComment              www.ErrorStatusT = 1035
	ErrorStatusInvalidDCCStatusTransition     www.ErrorStatusT = 1036
	ErrorStatusDuplicateEmail                 www.ErrorStatusT = 1037
	ErrorStatusInvalidUserNewInvoice          www.ErrorStatusT = 1038
)

var (
	// PolicyValidMimeTypes is the accepted mime types of attachments
	// in invoices
	PolicyValidMimeTypes = []string{
		"image/png",
	}

	// PolicyInvoiceFieldSupportedChars is the regular expression of a valid
	// invoice fields.
	PolicyInvoiceFieldSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'"}

	// PolicyCMSNameLocationSupportedChars is the regular expression of a valid
	// name or location for registering users on cms.
	PolicyCMSNameLocationSupportedChars = []string{
		"A-z", "0-9", ".", "-", " ", ","}

	// PolicyCMSContactSupportedChars is the regular expression of a valid
	// contact for registering users on cms.
	PolicyCMSContactSupportedChars = []string{
		"A-z", "0-9", "&", ".", ":", "-", "_", "@", "+", ",", " "}

	// PolicySponsorStatementSupportedChars is the regular expression of a valid
	// sponsor statement for DCC in cms.
	PolicySponsorStatementSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'"}

	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[www.ErrorStatusT]string{
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
		ErrorStatusInvoiceMissingLocation:         "invoice missing contractor location",
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
	}
)

/// Contractor Management System Routes

// InviteNewUser is used to request that a new user invitation be sent via email.
// If successful, the user will require verification before being able to login.
type InviteNewUser struct {
	Email string `json:"email"`
}

// InviteNewUserReply responds with the verification token for the user
// (if an email server is not set up).
type InviteNewUserReply struct {
	VerificationToken string `json:"verificationtoken"`
}

// RegisterUser is used by an contractor that has been invited to join the
// Contractor Management System
type RegisterUser struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	VerificationToken string `json:"verificationtoken"`
	PublicKey         string `json:"publickey"`
}

// RegisterUserReply replies to Register with no properties, if successful.
type RegisterUserReply struct{}

// NewInvoice attempts to submit a new invoice.
type NewInvoice struct {
	Month     uint       `json:"month"`
	Year      uint       `json:"year"`
	Files     []www.File `json:"files"`     // Invoice file and any attachments along with it
	PublicKey string     `json:"publickey"` // Key used to verify signature
	Signature string     `json:"signature"` // Signature of file hash
}

// NewInvoiceReply is used to reply to the NewInvoiceReply command.
type NewInvoiceReply struct {
	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// EditInvoice attempts to edit a proposal
type EditInvoice struct {
	Token     string     `json:"token"`
	Files     []www.File `json:"files"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// EditInvoiceReply is used to reply to the EditInvoice command
type EditInvoiceReply struct {
	Invoice InvoiceRecord `json:"invoice"`
}

// InvoiceRecord is an entire invoice and its content.
type InvoiceRecord struct {
	Status             InvoiceStatusT `json:"status"`                       // Current status of invoice
	StatusChangeReason string         `json:"statuschangereason,omitempty"` // Reason (if any) for the current status
	Timestamp          int64          `json:"timestamp"`                    // Last update of invoice
	UserID             string         `json:"userid"`                       // ID of user who submitted invoice
	Username           string         `json:"username"`                     // Username of user who submitted invoice
	PublicKey          string         `json:"publickey"`                    // User's public key, used to verify signature.
	Signature          string         `json:"signature"`                    // Signature of file digest
	Files              []www.File     `json:"file"`                         // Actual invoice file
	Version            string         `json:"version"`                      // Record version
	Input              InvoiceInput   `json:"input"`                        // Decoded invoice from invoice.json file

	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// InvoiceDetails is used to retrieve a invoice by it's token.
type InvoiceDetails struct {
	Token string `json:"token"` // Censorship token
}

// InvoiceDetailsReply is used to reply to a invoice details command.
type InvoiceDetailsReply struct {
	Invoice InvoiceRecord `json:"invoice"`
	Payout  Payout        `json:"payout"` // Calculated payout from the InvoiceRecord
}

// InvoiceInput is the expected structure of the invoice.json file being added to InvoiceRecords.
// Users' raw csv will be inputted and parsed to help in their creation.
type InvoiceInput struct {
	Version            uint             `json:"version"`            // Version of the invoice input
	Month              uint             `json:"month"`              // Month of Invoice
	Year               uint             `json:"year"`               // Year of Invoice
	ExchangeRate       uint             `json:"exchangerate"`       // Exchange rate of a given month/year in USD cents
	ContractorName     string           `json:"contractorname"`     // IRL name of contractor
	ContractorLocation string           `json:"contractorlocation"` // IRL location of contractor
	ContractorContact  string           `json:"contractorcontact"`  // Contractor email or other contact
	ContractorRate     uint             `json:"contractorrate"`     // Contractor Pay Rate in USD cents
	PaymentAddress     string           `json:"paymentaddress"`     //  DCR payment address
	LineItems          []LineItemsInput `json:"lineitems"`
}

// LineItemsInput is the expected struct of line items contained within an users'
// invoice input.
type LineItemsInput struct {
	Type          LineItemTypeT `json:"type"`          // Type of work performed
	Domain        string        `json:"domain"`        // Domain of work performed
	Subdomain     string        `json:"subdomain"`     // Subdomain of work performed
	Description   string        `json:"description"`   // Description of work performed
	ProposalToken string        `json:"proposaltoken"` // Link to politeia proposal that work is associated with
	Labor         uint          `json:"labor"`         // Number of minutes (if labor)
	Expenses      uint          `json:"expenses"`      // Total cost (in USD cents) of line item (if expense or misc)
}

// PolicyReply for returns the various policy information while in CMS mode.
type PolicyReply struct {
	MinPasswordLength             uint     `json:"minpasswordlength"`
	MinUsernameLength             uint     `json:"minusernamelength"`
	MaxUsernameLength             uint     `json:"maxusernamelength"`
	MaxImages                     uint     `json:"maximages"`
	MaxImageSize                  uint     `json:"maximagesize"`
	MaxMDs                        uint     `json:"maxmds"`
	MaxMDSize                     uint     `json:"maxmdsize"`
	ValidMIMETypes                []string `json:"validmimetypes"`
	MaxNameLength                 uint     `json:"maxnamelength"`
	MinNameLength                 uint     `json:"minnamelength"`
	MaxLocationLength             uint     `json:"maxlocationlength"`
	MinLocationLength             uint     `json:"minlocationlength"`
	MaxContactLength              uint     `json:"maxcontactlength"`
	MinContactLength              uint     `json:"mincontactlength"`
	MaxLineItemColLength          uint     `json:"maxlineitemcollength"`
	MinLineItemColLength          uint     `json:"minlineitemcollength"`
	InvoiceCommentChar            rune     `json:"invoicecommentchar"`
	InvoiceFieldDelimiterChar     rune     `json:"invoicefielddelimiterchar"`
	InvoiceLineItemCount          uint     `json:"invoicelineitemcount"`
	InvoiceFieldSupportedChars    []string `json:"invoicefieldsupportedchars"`
	CMSUsernameSupportedChars     []string `json:"cmsusernamesupportedchars"`
	CMSNameLocationSupportedChars []string `json:"cmsnamelocationsupportedchars"`
	CMSContactSupportedChars      []string `json:"cmscontactsupportedchars"`
}

// UserInvoices is used to get all of the invoices by userID.
type UserInvoices struct{}

// UserInvoicesReply is used to reply to a user invoices commands.
type UserInvoicesReply struct {
	Invoices []InvoiceRecord `json:"invoices"`
}

// AdminInvoices is used to get all invoices from all users
type AdminInvoices struct {
	Month  uint16         `json:"month"`  // Month of Invoice
	Year   uint16         `json:"year"`   // Year of Invoice
	Status InvoiceStatusT `json:"status"` // Current status of invoice
}

// AdminInvoicesReply is used to reply to an admin invoices command.
type AdminInvoicesReply struct {
	Invoices []InvoiceRecord `json:"invoices"`
}

// AdminUserInvoices is used to get all invoices from a given user
type AdminUserInvoices struct {
	UserID string `json:"userid"` // Invoices from a given user
}

// AdminUserInvoicesReply is used to reply to a user invoices commands.
type AdminUserInvoicesReply struct {
	Invoices []InvoiceRecord `json:"invoices"`
}

// SetInvoiceStatus is used to approve or reject an unreviewed invoice.
type SetInvoiceStatus struct {
	Token     string         `json:"token"`
	Status    InvoiceStatusT `json:"status"`
	Reason    string         `json:"reason"`
	Signature string         `json:"signature"` // Signature of Token+Version+Reason(InvoiceStatus)
	PublicKey string         `json:"publickey"` // Public key of admin
}

// SetInvoiceStatusReply is used to reply to a SetInvoiceStatus command.
type SetInvoiceStatusReply struct {
	Invoice InvoiceRecord `json:"invoice"`
}

// GeneratePayouts is used to generate a list of addresses and amounts of
// approved invoices that need to be paid.
type GeneratePayouts struct {
}

// GeneratePayoutsReply is used to replay to a GeneratePayouts command.
type GeneratePayoutsReply struct {
	Payouts []Payout `json:"payouts"`
}

// Payout contains an address and an amount to be paid
type Payout struct {
	ContractorName string         `json:"contractorname"`
	ContractorRate uint           `json:"contractorrate"` // in USD cents
	Username       string         `json:"username"`
	Month          uint           `json:"month"`        // Invoice month
	Year           uint           `json:"year"`         // Invoice year
	Token          string         `json:"token"`        // Invoice token
	Address        string         `json:"address"`      // User provided payment address
	LaborTotal     uint           `json:"labortotal"`   // in USD cents
	ExpenseTotal   uint           `json:"expensetotal"` // in USD cents
	Total          uint           `json:"total"`        // in USD cents
	DCRTotal       dcrutil.Amount `json:"dcrtotal"`     // in DCR atoms
	ExchangeRate   uint           `json:"exchangerate"` // in USD cents
	ApprovedTime   int64          `json:"approvedtime"` // Time of invoice approval (in Unix seconds)
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

// PayInvoices temporarily allows the administrator to set all approved invoices
// to paid status.
type PayInvoices struct{}

// PayInvoicesReply will be empty if no errors have occurred.
type PayInvoicesReply struct{}

// LineItemPayouts contains the request to receive line items from payouts
// within a start and end date.
type LineItemPayouts struct {
	StartTime int64 `json:"starttime"` // Start time for range (in unix seconds)
	EndTime   int64 `json:"endtime"`   // End time for rang (in unix seconds)
}

// LineItemPayoutsReply returns an array of line items within the requested
// date range.
type LineItemPayoutsReply struct {
	LineItems []LineItemsInput `json:"lineitems"` // Line items within the requested date range.
}

// PaymentInformation contains information for each invoice's payout. A payout
// might be a single transaction or it might include multiple transactions.
type PaymentInformation struct {
	Token           string         `json:"token"`
	Address         string         `json:"address"`
	TxIDs           []string       `json:"txids"`
	TimeStarted     int64          `json:"timestarted"`
	TimeLastUpdated int64          `json:"timelastupdated"`
	AmountNeeded    dcrutil.Amount `json:"amountneeded"`
	AmountReceived  dcrutil.Amount `json:"amountreceived"`
	Status          PaymentStatusT `json:"status"`
}

// User represents a CMS user. It contains the standard politeiawww user
// fields as well as CMS specific user fields.
type User struct {
	ID                              string             `json:"id"`
	Email                           string             `json:"email"`
	Username                        string             `json:"username"`
	Admin                           bool               `json:"isadmin"`
	Identities                      []www.UserIdentity `json:"identities"`
	LastLoginTime                   int64              `json:"lastlogintime"`
	FailedLoginAttempts             uint64             `json:"failedloginattempts"`
	Deactivated                     bool               `json:"isdeactivated"`
	Locked                          bool               `json:"islocked"`
	EmailNotifications              uint64             `json:"emailnotifications"` // Notify the user via emails
	NewUserVerificationToken        []byte             `json:"newuserverificationtoken"`
	NewUserVerificationExpiry       int64              `json:"newuserverificationexpiry"`
	UpdateKeyVerificationToken      []byte             `json:"updatekeyverificationtoken"`
	UpdateKeyVerificationExpiry     int64              `json:"updatekeyverificationexpiry"`
	ResetPasswordVerificationToken  []byte             `json:"resetpasswordverificationtoken"`
	ResetPasswordVerificationExpiry int64              `json:"resetpasswordverificationexpiry"`

	// CMS Information
	Domain             DomainTypeT     `json:"domain"` // Contractor domain
	GitHubName         string          `json:"githubname"`
	MatrixName         string          `json:"matrixname"`
	ContractorType     ContractorTypeT `json:"contractortype"`
	ContractorName     string          `json:"contractorname"`
	ContractorLocation string          `json:"contractorlocation"`
	ContractorContact  string          `json:"contractorcontact"`
	SupervisorUserID   string          `json:"supervisoruserid"`
}

// UserDetails fetches a cms user's details by their id.
type UserDetails struct {
	UserID string `json:"userid"` // User id
}

// UserDetailsReply returns a cms user's details.
type UserDetailsReply struct {
	User User `json:"user"`
}

// EditUser edits a user's preferences.
type EditUser struct {
	Domain             DomainTypeT     `json:"domain,omitempty"` // Contractor domain
	GitHubName         string          `json:"githubname,omitempty"`
	MatrixName         string          `json:"matrixname,omitempty"`
	ContractorType     ContractorTypeT `json:"contractortype,omitempty"`
	ContractorName     string          `json:"contractorname,omitempty"`
	ContractorLocation string          `json:"contractorlocation,omitempty"`
	ContractorContact  string          `json:"contractorcontact,omitempty"`
	SupervisorUserID   string          `json:"supervisoruserid,omitempty"`
}

// EditUserReply is the reply for the EditUser command.
type EditUserReply struct{}

// DCCInput contains all of the information concerning a DCC object that
// will be submitted as a Record to the politeiad backend.
type DCCInput struct {
	Type          DCCTypeT `json:"type"`          // Type of DCC object
	NomineeUserID string   `json:"nomineeuserid"` // UserID of the DCC nominee (issuance or revocation)
	//SponsorUserID    string      `json:"sponsoruserid"` // UserID of the sponsoring user
	SponsorStatement string      `json:"statement"` // Statement from sponsoring user about why DCC should be approved
	Domain           DomainTypeT `json:"domain"`    // Domain of proposed contractor issuance
}

// DCCRecord is what will be decoded from a Record for a DCC object to the politeiad backend.
type DCCRecord struct {
	Type               DCCTypeT   `json:"type"`               // Type of DCC
	Status             DCCStatusT `json:"status"`             // Current status of the DCC
	StatusChangeReason string     `json:"statuschangereason"` // The reason for changing the DCC status.
	Timestamp          int64      `json:"timestamp"`          // Last update of dcc
	DCC                DCCInput   `json:"dccpayload"`         // DCC payload for the given object
	Files              []www.File `json:"file"`               // Actual DCC files (dcc.json, etc)
	PublicKey          string     `json:"publickey"`          // Sponsoring user's public key, used to verify signature.
	Signature          string     `json:"signature"`          // Signature of file digest
	Version            string     `json:"version"`            // Record version

	SponsorStatement string      `json:"statement"` // Sponsor statement in support of the DCC
	Domain           DomainTypeT `json:"domain"`    // Domain of DCC

	SponsorUserID   string `json:"sponsoruserid"`   // The userid of the sponsoring user.
	SponsorUsername string `json:"sponsorusername"` // The username of the sponsoring user.

	SupportUserIDs    []string `json:"supportuserids"` // List of UserIDs for those that have shown support of the DCC.
	OppositionUserIDs []string `json:"againstuserids"` // List of UserIDs for those that have shown opposition of the DCC.

	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// NewDCC is a request for submitting a new DCC proposal.
type NewDCC struct {
	Files     []www.File `json:"files"`     // Issuance/Revocation file and any attachments along with it
	PublicKey string     `json:"publickey"` // Pubkey of the sponsoring user
	Signature string     `json:"signature"` // Signature of the issuance struct by the sponsoring user.
}

// NewDCCReply returns the censorship record when the DCC is successfully submitted to the backend.
type NewDCCReply struct {
	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// NewDCCUser request adds a new user to the userdb (much like Invite), but this
// user's information and access is limited until they are fully approved.
type NewDCCUser struct {
	ContractorName    string `json:"contractorname"`
	ContractorContact string `json:"contractorcontact"`
	ContractorEmail   string `json:"contractoremail"`
	Signature         string `json:"signature"` // Signature of name + contact + email
	PublicKey         string `json:"publickey"` // Public key of user
}

// NewDCCUserReply returns an empty response when successful.
type NewDCCUserReply struct {
	UserID string `json:"userid"` // UserID of the newly created nominee user.
}

// DCCDetails request finds a DCC with a matching token.
type DCCDetails struct {
	Token string `json:"token"` // Token of requested DCC
}

// DCCDetailsReply returns the DCC details if found.
type DCCDetailsReply struct {
	DCC DCCRecord `json:"dcc"` // DCCRecord of requested token
}

// GetDCCs request finds all DCCs that have matching status (if used).
type GetDCCs struct {
	Status DCCStatusT `json:"status"` // Return all DCCs of this status
}

// GetDCCsReply returns the DCCs if found.
type GetDCCsReply struct {
	DCCs []DCCRecord `json:"dccs"` // DCCRecords of matching status
}
