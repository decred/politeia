// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"
)

var (
	// ErrNoVersionRecord is emitted when no version record exists.
	ErrNoVersionRecord = errors.New("no version record")

	// ErrNoPullRequestFound is emitted when no pull request matches.
	ErrNoPullRequestFound = errors.New("no pull request found")

	// ErrWrongVersion is emitted when the version record does not
	// match the implementation version.
	ErrWrongVersion = errors.New("wrong version")

	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")
)

// Database interface that is required by the web server.
type Database interface {
	NewPullRequest(*PullRequest) error    // Create new pull request
	UpdatePullRequest(*PullRequest) error // Update exisiting pull request
	PullRequestByURL(string) (*PullRequest, error)
	PullRequestsByUserDates(string, int64, int64) ([]*PullRequest, error) // Retrieve all pull requests that match username between dates

	AllUsersByDates(int64, int64) ([]string, error)

	NewCommit(*Commit) error    // Create new commit
	UpdateCommit(*Commit) error // Update existing commit

	NewPullRequestReview(*PullRequestReview) error                        // Create new pull request review
	UpdatePullRequestReview(*PullRequestReview) error                     // Update existing pull request review
	ReviewsByUserDates(string, int64, int64) ([]PullRequestReview, error) // Retrieve all reviews that match username between dates

	Setup() error

	// Close performs cleanup of the backend.
	Close() error
}

type PullRequest struct {
	Repo         string
	Organization string
	User         string
	URL          string
	Number       int
	UpdatedAt    int64
	ClosedAt     int64
	MergedAt     int64
	Merged       bool
	State        string
	Additions    int
	Deletions    int
	MergedBy     string

	Commits []Commit
	Reviews []PullRequestReview
}

type Commit struct {
	SHA       string
	URL       string
	Message   string
	Author    string
	Committer string
	Additions int
	Deletions int
}

type PullRequestReview struct {
	ID          int64
	Author      string
	State       string
	SubmittedAt int64
	CommitID    string
	Repo        string
	Number      int
	Additions   int
	Deletions   int
}

/*
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
*/
