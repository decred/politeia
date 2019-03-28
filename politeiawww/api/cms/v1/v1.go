package v1

import (
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

type InvoiceStatusT int

const (

	// Contractor Management Routes

	RouteInviteNewUser  = "/invite"
	RouteRegisterUser   = "/register"
	RouteNewInvoice     = "/invoices/new"
	RouteInvoiceDetails = "/invoices/{token:[A-z0-9]{64}}"
	RouteUserInvoices   = "/user/invoices"
	RouteAdminInvoices  = "/admin/invoices"

	// Invoice status codes
	InvoiceStatusInvalid  InvoiceStatusT = 0 // Invalid status
	InvoiceStatusNotFound InvoiceStatusT = 1 // Invoice not found
	InvoiceStatusNew      InvoiceStatusT = 2 // Invoice has not been reviewed
	InvoiceStatusUpdated  InvoiceStatusT = 3 // Invoice has unreviewed changes
	InvoiceStatusDisputed InvoiceStatusT = 4 // Invoice has been disputed for some reason
	InvoiceStatusRejected InvoiceStatusT = 5 // Invoice fully rejected and closed
	InvoiceStatusApproved InvoiceStatusT = 6 // Invoice has been approved
	InvoiceStatusPaid     InvoiceStatusT = 7 // Invoice has been paid
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
	Name              string `json:"name"`       // User's full name
	Location          string `json:"location"`   // User's physical location
	ExtendedPublicKey string `json:"xpublickey"` // Extended public key for user's payment account
	VerificationToken string `json:"verificationtoken"`
	PublicKey         string `json:"publickey"`
}

// RegisterUserReply replies to Register with no properties, if successful.
type RegisterUserReply struct{}

// NewInvoice attempts to submit a new invoice.
type NewInvoice struct {
	Month     uint16     `json:"month"`
	Year      uint16     `json:"year"`
	Files     []www.File `json:"files"`     // Invoice file and any attachments along with it
	PublicKey string     `json:"publickey"` // Key used to verify signature
	Signature string     `json:"signature"` // Signature of file hash
}

// NewInvoiceReply is used to reply to the NewInvoiceReply command.
type NewInvoiceReply struct {
	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// InvoiceRecord is an entire invoice and its content.
type InvoiceRecord struct {
	Status             InvoiceStatusT `json:"status"`                       // Current status of invoice
	StatusChangeReason string         `json:"statuschangereason,omitempty"` // Reason (if any) for the current status
	Timestamp          int64          `json:"timestamp"`                    // Last update of invoice
	Month              uint16         `json:"month"`                        // The month that this invoice applies to
	Year               uint16         `json:"year"`                         // The year that this invoice applies to
	UserID             string         `json:"userid"`                       // ID of user who submitted invoice
	Username           string         `json:"username"`                     // Username of user who submitted invoice
	PublicKey          string         `json:"publickey"`                    // User's public key, used to verify signature.
	Signature          string         `json:"signature"`                    // Signature of file digest
	Files              []www.File     `json:"file"`                         // Actual invoice file
	Version            string         `json:"version"`                      // Record version

	CensorshipRecord www.CensorshipRecord `json:"censorshiprecord"`
}

// InvoiceDetails is used to retrieve a invoice by it's token.
type InvoiceDetails struct {
	Token string `json:"token"` // Censorship token
}

// InvoiceDetailsReply is used to reply to a invoice details command.
type InvoiceDetailsReply struct {
	Invoice InvoiceRecord `json:"invoice"`
}

// InvoiceInput is the expected structure of the invoice.json file being added to InvoiceRecords.
// Users' raw csv will be inputted and parsed to help in their creation.
type InvoiceInput struct {
	ID        string           `json:"id"`    // Optional field for contractor ID entry
	Month     uint16           `json:"month"` // Month of Invoice
	Year      uint16           `json:"year"`  // Year of Invoice
	LineItems []LineItemsInput `json:"lineitems"`
}

// LineItemsInput is the expected struct of line items contained within an users'
// invoice input.
type LineItemsInput struct {
	LineNumber    uint16  `json:"linenum"`       // Line number of the line item
	Type          string  `json:"type"`          // Type of work performed
	Subtype       string  `json:"subtype"`       // Subtype of work performed
	Description   string  `json:"description"`   // Description of work performed
	ProposalToken string  `json:"proposaltoken"` // Link to politeia proposal that work is associated with
	Hours         float64 `json:"hours"`         // Number of Hours
	TotalCost     float64 `json:"totalcost"`     // Total cost of line item
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

// AdminInvoiceReply is used to reply to an admin invoices command.
type AdminInvoicesReply struct {
	Invoices []InvoiceRecord `json:"invoices"`
}
