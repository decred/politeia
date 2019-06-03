// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"time"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// Invoice is the database model for the database.Invoice type
type Invoice struct {
	Token              string    `gorm:"primary_key"`
	UserID             string    `gorm:"not null"`
	Username           string    `gorm:"-"` // Only populated when reading from the database
	Month              uint      `gorm:"not null"`
	Year               uint      `gorm:"not null"`
	ExchangeRate       uint      `gorm:"not null"`
	Timestamp          time.Time `gorm:"not null"`
	Status             uint      `gorm:"not null"`
	StatusChangeReason string    `gorm:"not null"`
	PublicKey          string    `gorm:"not null"`
	UserSignature      string    `gorm:"not null"`
	ServerSignature    string    `gorm:"not null"`
	Version            string    `gorm:"not null"`
	ContractorName     string    `gorm:"not null"`
	ContractorLocation string    `gorm:"not null"`
	ContractorRate     uint      `gorm:"not null"`
	ContractorContact  string    `gorm:"not null"`
	PaymentAddress     string    `gorm:"not null"`

	LineItems []LineItem      `gorm:"foreignkey:InvoiceToken"`
	Changes   []InvoiceChange `gorm:"foreignkey:InvoiceToken"`
	Payments  Payments        `gorm:"foreignkey:InvoiceToken"`
}

// TableName returns the table name of the invoices table.
func (Invoice) TableName() string {
	return tableNameInvoice
}

// LineItem is the database model for the database.LineItem type
type LineItem struct {
	LineItemKey  string `gorm:"primary_key"` // Token of the Invoice + array index
	InvoiceToken string `gorm:"not null"`    // Censorship token of the invoice
	Type         uint   `gorm:"not null"`    // Type of line item
	Domain       string `gorm:"not null"`    // Domain of the work performed (dev, marketing etc)
	Subdomain    string `gorm:"not null"`    // Subdomain of the work performed (decrediton, event X etc)
	Description  string `gorm:"not null"`    // Description of work performed
	ProposalURL  string `gorm:"not null"`    // Link to politeia proposal that work is associated with
	Labor        uint   `gorm:"not null"`    // Number of minutes worked
	Expenses     uint   `gorm:"not null"`    // Total cost of line item (in USD cents)
}

// TableName returns the table name of the line items table.
func (LineItem) TableName() string {
	return tableNameLineItem
}

// InvoiceChange contains entries for any status update that occurs to a given
// invoice.  This will give a full history of an invoices history.
type InvoiceChange struct {
	InvoiceToken   string    `gorm:"not null"` // Censorship token of the invoice
	AdminPublicKey string    `gorm:"not null"` // The public of the admin that processed the status change.
	NewStatus      uint      `gorm:"not null"` // Updated status of the invoice.
	Reason         string    `gorm:"not null"` // Reason for status updated (required if rejected)
	Timestamp      time.Time `gorm:"not null"` // The timestamp of the status change.
}

// TableName returns the table name of the line items table.
func (InvoiceChange) TableName() string {
	return tableNameInvoiceChange
}

// ExchangeRate contains cached calculated rates for a given month/year
type ExchangeRate struct {
	Month        uint `gorm:"not null"`
	Year         uint `gorm:"not null"`
	ExchangeRate uint `gorm:"not null"`
}

// TableName returns the table name of the line items table.
func (ExchangeRate) TableName() string {
	return tableNameExchangeRate
}

// Payments contains all the information about a given invoice's payment
type Payments struct {
	InvoiceToken    string `gorm:"primary_key"`
	Address         string `gorm:"not null"`
	TxIDs           string `gorm:"not null"`
	TimeStarted     int64  `gorm:"not null"`
	TimeLastUpdated int64  `gorm:"not null"`
	AmountNeeded    int64  `gorm:"not null"`
	AmountReceived  int64  `gorm:"not null"`
	Status          uint   `gorm:"not null"`
}

// TableName returns the table name of the line items table.
func (Payments) TableName() string {
	return tableNamePayments
}
