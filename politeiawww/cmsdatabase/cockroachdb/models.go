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
	UserID             string    `gorm:"not_null"`
	Username           string    `gorm:"-"` // Only populated when reading from the database
	Month              uint      `gorm:"not_null"`
	Year               uint      `gorm:"not_null"`
	Timestamp          time.Time `gorm:"not_null"`
	Status             uint      `gorm:"not_null"`
	StatusChangeReason string    `gorm:"not_null"`
	PublicKey          string    `gorm:"not_null"`
	UserSignature      string    `gorm:"not_null"`
	ServerSignature    string    `gorm:"not_null"`
	Version            string    `gorm:"not_null"`

	LineItems []LineItem `gorm:"not_null"`
}

// TableName returns the table name of the invoices table.
func (Invoice) TableName() string {
	return tableNameInvoice
}

// LineItem is the database model for the database.LineItem type
type LineItem struct {
	LineNumber   uint    `gorm:"not_null"` // LineNumber of each line item
	InvoiceToken string  `gorm:"not_null"` // Token of the Invoice that has this lineitem
	Type         string  `gorm:"not_null"` // Type of work performed
	Subtype      string  `gorm:"not_null"` // Subtype of work performed
	Description  string  `gorm:"not_null"` // Description of work performed
	ProposalURL  string  `gorm:"not_null"` // Link to politeia proposal that work is associated with
	Hours        float64 `gorm:"not_null"` // Number of Hours
	TotalCost    float64 `gorm:"not_null"` // Total cost of line item
}

// TableName returns the table name of the line items table.
func (LineItem) TableName() string {
	return tableNameLineItem
}
