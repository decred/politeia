// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cmsdatabase

import (
	"errors"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvoiceNotFound indicates that the invoice was not found in the
	// database.
	ErrInvoiceNotFound = errors.New("invoice not found")

	// ErrExchangeRateNotFound indicates that an exchange rate for a given month/year was not found
	ErrExchangeRateNotFound = errors.New("exchange rate not found")
)

// Database interface that is required by the web server.
type Database interface {
	// Invoice functions
	NewInvoice(*Invoice) error // Create new invoice

	UpdateInvoice(*Invoice) error // Update existing invoice
	InvoicesByUserID(string) ([]Invoice, error)
	InvoiceByToken(string) (*Invoice, error) // Return invoice given its token

	InvoicesByMonthYearStatus(uint16, uint16, int) ([]Invoice, error) // Returns all invoices by month, year and status
	InvoicesByMonthYear(uint16, uint16) ([]Invoice, error)            // Returns all invoice by month, year
	InvoicesByStatus(int) ([]Invoice, error)                          // Returns all invoices by status
	InvoicesAll() ([]Invoice, error)                                  // Returns all invoices

	// ExchangeRate functions
	NewExchangeRate(*ExchangeRate) error // Create new exchange rate

	ExchangeRate(int, int) (*ExchangeRate, error) // Return an exchange rate based on month and year
	// Setup the invoice tables
	Setup() error

	// Build the invoice tables from scratch (from inventory of d)
	Build(string) error

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
}

// LineItem contains information about the individual line items contained in an
// invoice coming into or out of the cmsdatabase.
type LineItem struct {
	LineNumber   uint
	InvoiceToken string
	Type         cms.LineItemTypeT
	Domain       string
	Subdomain    string
	Description  string
	ProposalURL  string
	Labor        uint
	Expenses     uint
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
