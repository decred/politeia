// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/google/uuid"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates that a user already exists in the database.
	ErrUserExists = errors.New("user already exists")

	// ErrInvalidEmail indicates that a user's email is not properly formatted.
	ErrInvalidEmail = errors.New("invalid user email")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")
)

// Identity wraps an ed25519 public key and timestamps to indicate if it is
// active.  If deactivated != 0 then the key is no longer valid.
type Identity struct {
	Key         [identity.PublicKeySize]byte // ed25519 public key
	Activated   int64                        // Time key as activated for use
	Deactivated int64                        // Time key was deactivated
}

// IsActive returns whether the identity is active.
func (i *Identity) IsActive() bool {
	return i.Activated != 0 && i.Deactivated == 0
}

// String returns a hex encoded string of the identity key.
func (i *Identity) String() string {
	return hex.EncodeToString(i.Key[:])
}

// A proposal paywall allows the user to purchase proposal credits.  Proposal
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

// A proposal credit allows the user to submit a new proposal.  Credits are
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

	// Contractor Management System fields
	Name              string // The real name associated with a Contractor
	Location          string // The general location provided by the Contractor
	ExtendedPublicKey string // The extendedpublickey provided by the Contractor that will be used to generate outgoing payments from invoices.

}

// ActiveIdentity returns a user's active identity. A user will always have an
// active identity. This function panics if this assumption does not hold.
func (u *User) ActiveIdentity() *Identity {
	for _, v := range u.Identities {
		if v.IsActive() {
			return &v
		}
	}
	panic(fmt.Sprintf("active identity not found "+
		"for user %v", u.ID.String()))
}

// PublicKey returns a hex encoded string of the user's active identity key.
func (u *User) PublicKey() string {
	return u.ActiveIdentity().String()
}

// Database interface that is required by the web server.
type Database interface {
	// User functions
	UserGet(string) (*User, error)           // Return user record, key is email
	UserGetByUsername(string) (*User, error) // Return user record given the username
	UserGetById(uuid.UUID) (*User, error)    // Return user record given its id
	UserNew(User) error                      // Add new user
	UserUpdate(User) error                   // Update existing user
	AllUsers(callbackFn func(u *User)) error // Iterate all users

	// Close performs cleanup of the backend.
	Close() error
}
