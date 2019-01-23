// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/google/uuid"
)

// RecordTypeT indetifies the struct type of a database record.
type RecordTypeT int

var (
	// ErrNotFound indicates that a provided key was not found
	// in the database.
	ErrNotFound = errors.New("key not found")

	// ErrUserExists indicates that a user already exists in the database.
	ErrUserExists = errors.New("user already exists")

	// ErrInvalidEmail indicates that a user's email is not properly formatted.
	ErrInvalidEmail = errors.New("invalid user email")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")

	// ErrWrongVersion is emitted when the version in the database
	// does not match version of the interface implementation.
	ErrWrongVersion = errors.New("wrong database version")

	// ErrWrongRecordVersion is emitted when the record version in the
	// database does not match the version of the interface implementation.
	ErrWrongRecordVersion = errors.New("wrong record version")

	// ErrWrongSnapshotVersion is emmited when the provided snapshot version
	// doesn not match the version of the interface implementation.
	ErrWrongSnapshotVersion = errors.New("wrong snapshot version")

	// ErrWrongRecordType is emitted when the record type in the database
	// does not match the expected type.
	ErrWrongRecordType = errors.New("wrong record type")

	// ErrWrongEncryptionKey is emitted when the database record cannot
	// be decrypted with the provided key.
	ErrWrongEncryptionKey = errors.New("Invalid database encryption key")
)

const (
	// DatabaseVersion is the current version of the database.
	DatabaseVersion uint32 = 1

	// DatabaseVersionKey is the key used to map the database version.
	DatabaseVersionKey = "userversion"

	// LastPaywallAddressIndexKey is the key used to map the last paywall index
	// for a user.
	LastPaywallAddressIndexKey = "lastpaywallindex"

	RecordTypeInvalid            RecordTypeT = 0 // Invalid record type
	RecordTypeUser               RecordTypeT = 1 // User record type
	RecordTypeVersion            RecordTypeT = 2 // Version record Type
	RecordTypeLastPaywallAddrIdx RecordTypeT = 3 // LastPaywallAddressIndex record type
)

// Snapshot wraps the database snapshot, the time when it was created
// and the version of the database.
type Snapshot struct {
	Snapshot map[string][]byte // The database snapshot
	Time     int64             // Time when the snapshot was created
	Version  uint32            // Database version when the snapshot was created
}

// EncryptionKey wraps a key used for encrypting/decrypting the database
// data and the time when it was created.
type EncryptionKey struct {
	Key  [32]byte // Key used for encryption
	Time int64    // Time key was created
}

// Identity wraps an ed25519 public key and timestamps to indicate if it is
// active.  If deactivated != 0 then the key is no longer valid.
type Identity struct {
	Key         [identity.PublicKeySize]byte // ed25519 public key
	Activated   int64                        // Time key was activated for use
	Deactivated int64                        // Time key was deactivated
}

// LastPaywallAddressIndex wraps the next paywall index to be used for
// the next user record inserted.
type LastPaywallAddressIndex struct {
	RecordType    RecordTypeT `json:"recordtype"`    // Record type
	RecordVersion uint32      `json:"recordversion"` // Database interface version

	Index uint64 `json:"index"`
}

// Version contains the database version.
type Version struct {
	RecordType    RecordTypeT `json:"recordtype"`    // Record type
	RecordVersion uint32      `json:"recordversion"` // Database interface version

	Version uint32 `json:"version"` // Database version
	Time    int64  `json:"time"`    // Time of record creation
}

// ProposalPaywall allows the user to purchase proposal credits.  Proposal
// paywalls are only valid for one tx.  The number of proposal credits created
// is determined by dividing the tx amount by the credit price.  Proposal
// paywalls expire after a set duration. politeiawww polls the paywall address
// for a payment tx until the paywall is either paid or it expires.
type ProposalPaywall struct {
	ID          uint64 // Paywall ID
	CreditPrice uint64 // Cost per proposal credit in atoms
	Address     string // Paywall address
	TxNotBefore int64  // Minimum timestamp for paywall tx
	PollExpiry  int64  // After this time, the paywall address will not be continuously polled
	TxID        string // Payment transaction ID
	TxAmount    uint64 // Amount sent to paywall address in atoms
	NumCredits  uint64 // Number of proposal credits created by payment tx
}

// ProposalCredit allows the user to submit a new proposal.  Credits are
// created when a user sends a payment to a proposal paywall.  A credit is
// automatically spent when a user submits a new proposal.  When a credit is
// spent, it is updated with the proposal's censorship token and moved to the
// user's spent proposal credits list.
type ProposalCredit struct {
	PaywallID       uint64 // ID of the proposal paywall that created this credit
	Price           uint64 // Price this credit was purchased at in atoms
	DatePurchased   int64  // Unix timestamp of when the credit was purchased
	TxID            string // Payment transaction ID
	CensorshipToken string // Censorship token of proposal that used this credit
}

// User record.
type User struct {
	RecordType    RecordTypeT // Record type
	RecordVersion uint32      // Database interface version

	ID                              uuid.UUID // Unique user uuid
	Email                           string    // Email address + lookup key.
	Username                        string    // Unique username
	HashedPassword                  []byte    // Blowfish hash
	Admin                           bool      // Is user an admin
	PaywallAddressIndex             uint64    // Sequential id used to generate paywall address
	NewUserPaywallAddress           string    // Address the user needs to send to
	NewUserPaywallAmount            uint64    // Amount the user needs to send
	NewUserPaywallTx                string    // Paywall transaction id
	NewUserPaywallTxNotBefore       int64     // Transactions occurring before this time will not be valid.
	NewUserPaywallPollExpiry        int64     // After this time, the user's paywall address will not be continuously polled
	NewUserVerificationToken        []byte    // New user registration verification token
	NewUserVerificationExpiry       int64     // New user registration verification expiration
	ResendNewUserVerificationExpiry int64     // Resend request for new user registration verification expiration
	UpdateKeyVerificationToken      []byte    // Verification token for updating keypair
	UpdateKeyVerificationExpiry     int64     // Verification expiration
	ResetPasswordVerificationToken  []byte    // Reset password token
	ResetPasswordVerificationExpiry int64     // Reset password token expiration
	LastLoginTime                   int64     // Unix timestamp of when the user last logged in
	FailedLoginAttempts             uint64    // Number of failed login a user has made in a row
	Deactivated                     bool      // Whether the account is deactivated or not
	EmailNotifications              uint64    // Notify the user via emails

	// Access times for proposal comments that have been accessed by the user.
	// Each string represents a proposal token, and the int64 represents the
	// time that the proposal has been most recently accessed in the format of
	// a UNIX timestamp.
	ProposalCommentsAccessTimes map[string]int64

	// All identities the user has ever used.  User should only have one
	// active key at a time.  We allow multiples in order to deal with key
	// loss.
	Identities []Identity

	// All proposal paywalls that have been issued to the user in chronological
	// order.
	ProposalPaywalls []ProposalPaywall

	// All proposal credits that have been purchased by the user, but have not
	// yet been used to submit a proposal.  Once a credit is used to submit a
	// proposal, it is updated with the proposal's censorship token and moved to
	// the user's spent proposal credits list.  The price that the proposal
	// credit was purchased at is in atoms.
	UnspentProposalCredits []ProposalCredit

	// All credits that have been purchased by the user and have already been
	// used to submit proposals.  Spent credits have a proposal censorship token
	// associated with them to signify that they have been spent. The price that
	// the proposal credit was purchased at is in atoms.
	SpentProposalCredits []ProposalCredit
}

// Database interface
type Database interface {
	Put(string, []byte) error                           // Set a record by key
	Get(string) ([]byte, error)                         // Get a database record by key
	Remove(string) error                                // Remove a record by key
	Has(string) (bool, error)                           // Returns true if the database has a key
	GetAll(callbackFn func(string, []byte) error) error // Iterate all database values
	GetSnapshot() (*Snapshot, error)                    // Get snapshot of the db at a particular point in time
	BuildFromSnapshot(Snapshot) error                   // Build the database from the provided snapshot

	Open() error  // Open a new database connection
	Close() error // Close the database connection
}
