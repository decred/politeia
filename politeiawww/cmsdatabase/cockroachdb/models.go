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
	Timestamp          time.Time `gorm:"not null"`
	Status             uint      `gorm:"not null"`
	StatusChangeReason string    `gorm:"not null"`
	PublicKey          string    `gorm:"not null"`
	UserSignature      string    `gorm:"not null"`
	ServerSignature    string    `gorm:"not null"`
	Version            string    `gorm:"not null"`

	LineItems []LineItem      `gorm:"foreignkey:InvoiceToken"`
	Changes   []InvoiceChange `gorm:"foreignkey:InvoiceToken"`
}

// TableName returns the table name of the invoices table.
func (Invoice) TableName() string {
	return tableNameInvoice
}

// LineItem is the database model for the database.LineItem type
type LineItem struct {
	LineItemKey  string  `gorm:"primary_key"` // Token of the Invoice + "-" + line number
	LineNumber   uint    `gorm:"not null"`    // Line number of the line item
	InvoiceToken string  `gorm:"not null"`    // Censorship token of the invoice
	Type         uint    `gorm:"not null"`    // Type of work performed
	Subtype      string  `gorm:"not null"`    // Subtype of work performed
	Description  string  `gorm:"not null"`    // Description of work performed
	ProposalURL  string  `gorm:"not null"`    // Link to politeia proposal that work is associated with
	Hours        float64 `gorm:"not null"`    // Number of Hours
	TotalCost    float64 `gorm:"not null"`    // Total cost of line item
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
