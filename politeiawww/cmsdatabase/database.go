// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cmsdatabase

import (
	"errors"

	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
)

var (
	// ErrNoVersionRecord is emitted when no version record exists.
	ErrNoVersionRecord = errors.New("no version record")

	// ErrWrongVersion is emitted when the version record does not
	// match the implementation version.
	ErrWrongVersion = errors.New("wrong version")

	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvoiceNotFound indicates that the invoice was not found in the
	// database.
	ErrInvoiceNotFound = errors.New("invoice not found")

	// ErrExchangeRateNotFound indicates that an exchange rate for a given month/year was not found
	ErrExchangeRateNotFound = errors.New("exchange rate not found")

	// ErrDCCNotFound indicates that a DCC was not found from a given token
	ErrDCCNotFound = errors.New("dcc not found")
)

// Database interface that is required by the web server.
type Database interface {
	// Invoice functions
	NewInvoice(*Invoice) error    // Create new invoice
	UpdateInvoice(*Invoice) error // Update existing invoice

	InvoicesByUserID(string) ([]Invoice, error)
	InvoiceByToken(string) (*Invoice, error)     // Return invoice given its token
	InvoicesByAddress(string) ([]Invoice, error) // Return invoice by its address

	InvoicesByMonthYearStatus(uint16, uint16, int) ([]Invoice, error) // Returns all invoices by month, year and status
	InvoicesByMonthYear(uint16, uint16) ([]Invoice, error)            // Returns all invoice by month, year
	InvoicesByStatus(int) ([]Invoice, error)                          // Returns all invoices by status
	InvoicesAll() ([]Invoice, error)                                  // Returns all invoices
	InvoicesByDateRangeStatus(int64, int64, int) ([]*Invoice, error)  // Returns all paid invoice line items from range provided

	// ExchangeRate functions
	NewExchangeRate(*ExchangeRate) error          // Create new exchange rate
	ExchangeRate(int, int) (*ExchangeRate, error) // Return an exchange rate based on month and year

	// Update Payments
	UpdatePayments(*Payments) error // Update existing payment information
	PaymentsByAddress(string) (*Payments, error)
	PaymentsByStatus(uint) ([]Payments, error)

	// DCC
	NewDCC(*DCC) error
	UpdateDCC(*DCC) error

	DCCByToken(string) (*DCC, error)
	DCCsByStatus(int) ([]*DCC, error)
	DCCsAll() ([]*DCC, error)

	// Setup the invoice tables
	Setup() error

	// Build the relevant tables of cmsdb from scratch
	Build([]Invoice, []DCC) error

	// Close performs cleanup of the backend.
	Close() error
}

// Invoice is the generic invoice type for invoices being added to or found
// in the cmsdatabase.
type Invoice struct {
	Token              string
	UserID             string
	Username           string // Only populated when reading from the database
	Month              uint
	Year               uint
	ExchangeRate       uint
	Timestamp          int64
	Status             cms.InvoiceStatusT
	StatusChangeReason string
	Files              []www.File
	PublicKey          string
	UserSignature      string
	ServerSignature    string
	Version            string // Version number of this invoice
	ContractorName     string
	ContractorLocation string
	ContractorContact  string
	ContractorRate     uint
	PaymentAddress     string

	LineItems []LineItem      // All line items parsed from the raw invoice provided.
	Changes   []InvoiceChange // All status changes that the invoice has had.
	Payments  Payments        // All payment information.
}

// LineItem contains information about the individual line items contained in an
// invoice coming into or out of the cmsdatabase.
type LineItem struct {
	LineNumber     uint
	InvoiceToken   string
	Type           cms.LineItemTypeT
	Domain         string
	Subdomain      string
	Description    string
	ProposalURL    string
	Labor          uint
	Expenses       uint
	ContractorRate uint
}

// InvoiceChange contains entries for any status update that occurs to a given
// invoice.  This will give a full history of an invoices history.
type InvoiceChange struct {
	AdminPublicKey string
	NewStatus      cms.InvoiceStatusT
	Reason         string
	Timestamp      int64
}

// ExchangeRate contains cached calculated rates for a given month/year
type ExchangeRate struct {
	Month        uint
	Year         uint
	ExchangeRate uint
}

// Payments contains information about each invoice's payments.
type Payments struct {
	InvoiceToken    string
	Address         string
	TxIDs           string
	TimeStarted     int64
	TimeLastUpdated int64
	AmountNeeded    int64
	AmountReceived  int64
	Status          cms.PaymentStatusT
}

// DCC contains information about a DCC proposal for issuance or revocation.
type DCC struct {
	Token              string
	SponsorUserID      string
	NomineeUserID      string
	Type               cms.DCCTypeT
	Status             cms.DCCStatusT
	Files              []www.File
	StatusChangeReason string
	Timestamp          int64
	PublicKey          string
	UserSignature      string
	ServerSignature    string
	SponsorStatement   string
	Domain             cms.DomainTypeT
	ContractorType     cms.ContractorTypeT

	SupportUserIDs    string
	OppositionUserIDs string
}
