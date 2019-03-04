// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

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
)

// Database interface that is required by the web server.
type Database interface {
	// Invoice functions
	NewInvoice(*Invoice) error // Create new invoice

	UpdateInvoice(*Invoice) error // Update existing invoice

	InvoiceByToken(string) (*Invoice, error) // Return invoice given its token

	// Setup the invoice tables
	Setup() error

	// Build the invoice tables from scratch (from inventory of d)
	Build(string) error

	// Close performs cleanup of the backend.
	Close() error
}

type Invoice struct {
	Token              string
	UserID             string
	Username           string // Only populated when reading from the database
	Month              uint16
	Year               uint16
	Timestamp          int64
	Status             cms.InvoiceStatusT
	StatusChangeReason string
	Files              []www.File
	PublicKey          string
	UserSignature      string
	ServerSignature    string
	Version            string // Version number of this invoice

	LineItems []LineItem
}

type LineItem struct {
	LineNumber   uint16
	InvoiceToken string
	Type         string
	Subtype      string
	Description  string
	ProposalURL  string
	Hours        uint16
	TotalCost    uint16
}
