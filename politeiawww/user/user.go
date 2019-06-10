// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/google/uuid"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates that a user already exists in the database.
	ErrUserExists = errors.New("user already exists")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")
)

// Identity wraps an ed25519 public key and timestamps to indicate if it is
// active. An identity can be in one of three states: inactive, active, or
// deactivated.
//
// inactive: Activated == 0 && Deactivated == 0
// The identity has been created, but has not yet been activated.
//
// active: Activated != 0 && Deactivated == 0
// The identity has been created and has been activated.
//
// deactivated: Deactivated != 0
// The identity in no longer active and the key is no longer valid.
type Identity struct {
	Key         [identity.PublicKeySize]byte // ed25519 public key
	Activated   int64                        // Time key as activated for use
	Deactivated int64                        // Time key was deactivated
}

// Activate activates the identity by setting the activated timestamp.
func (i *Identity) Activate() {
	i.Activated = time.Now().Unix()
}

// Deactivate deactivates the identity by setting the deactivated timestamp.
func (i *Identity) Deactivate() {
	i.Deactivated = time.Now().Unix()
}

// IsInactive returns whether the identity is inactive.
func (i *Identity) IsInactive() bool {
	return i.Activated == 0 && i.Deactivated == 0
}

// IsActive returns whether the identity is active.
func (i *Identity) IsActive() bool {
	return i.Activated != 0 && i.Deactivated == 0
}

// String returns a hex encoded string of the identity key.
func (i *Identity) String() string {
	return hex.EncodeToString(i.Key[:])
}

// NewIdentity returns a new inactive identity that was created using the
// provided public key.
func NewIdentity(publicKey string) (*Identity, error) {
	b, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	var empty [identity.PublicKeySize]byte
	switch {
	case len(b) != len(empty):
		return nil, fmt.Errorf("invalid length")
	case bytes.Equal(b, empty[:]):
		return nil, fmt.Errorf("empty bytes")
	}

	id := Identity{}
	copy(id.Key[:], b)
	return &id, nil
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

// VersionUser is the version of the User struct.
const VersionUser uint32 = 1

// User is a politeiawww user.
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

	// All identities the user has ever used. We allow the user to change
	// identities to deal with key loss. An identity can be in one of three
	// states: inactive, active, or deactivated.
	//
	// Inactive identities
	// An identity is consider inactive until it has been verified.
	// An unverified user will have an inactive identity.
	// A user will only ever have one inactive identity at a time.
	//
	// Active identities
	// A verified user will always have one active identity.
	// A verified user may have both an active and inactive identity if
	// they have requested a new identity but have not yet verified it.
	//
	// Deactivated identities
	// An identity is deactivated when it is replaced by a new identity.
	// The key of a deactivated identity is no longer valid.
	// An identity cannot be re-activated once it has been deactivated.
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

// ActiveIdentity returns the active identity for the user if one exists.
func (u *User) ActiveIdentity() *Identity {
	for k, v := range u.Identities {
		if v.IsActive() {
			return &u.Identities[k]
		}
	}
	return nil
}

// InactiveIdentity returns the inactive identity for the user if one exists.
func (u *User) InactiveIdentity() *Identity {
	for k, v := range u.Identities {
		if v.IsInactive() {
			return &u.Identities[k]
		}
	}
	return nil
}

// PublicKey returns a hex encoded string of the user's identity.
func (u *User) PublicKey() string {
	if u.ActiveIdentity() != nil {
		return u.ActiveIdentity().String()
	}
	if u.InactiveIdentity() != nil {
		return u.InactiveIdentity().String()
	}
	return ""
}

// AddIdentity adds the provided inactive identity to the identities array for
// the user. Any existing inactive identities are deactivated. A user should
// only ever have one inactive identity at a time, but due to a prior bug, this
// may not always be the case.
func (u *User) AddIdentity(id Identity) error {
	if u.Identities == nil {
		u.Identities = make([]Identity, 0)
	}

	// Validate provided identity
	for _, v := range u.Identities {
		if bytes.Equal(v.Key[:], id.Key[:]) {
			if v.IsInactive() {
				// Inactive identity has already been
				// added. This is ok.
				return nil
			}
			return fmt.Errorf("duplicate key")
		}
	}
	switch {
	case id.Deactivated != 0:
		return fmt.Errorf("identity is deactivated")
	case id.Activated != 0:
		return fmt.Errorf("identity is activated")
	}

	// Deactivate any existing inactive identities
	for k, v := range u.Identities {
		if v.IsInactive() {
			u.Identities[k].Deactivate()
		}
	}

	// Add new inactive identity
	u.Identities = append(u.Identities, id)

	return nil
}

// ActivateIdentity sets the identity associated with the provided key as the
// active identity for the user. The provided key must correspond to an
// inactive identity. If there is an existing active identity, it wil be
// deactivated.
func (u *User) ActivateIdentity(key []byte) error {
	if u.Identities == nil {
		return fmt.Errorf("identity not found")
	}

	// Ensure provided key exists and is inactive
	var inactive *Identity
	for k, v := range u.Identities {
		if bytes.Equal(v.Key[:], key[:]) {
			inactive = &u.Identities[k]
			break
		}
	}
	switch {
	case inactive == nil:
		return fmt.Errorf("identity not found")
	case inactive.Deactivated != 0:
		return fmt.Errorf("identity is deactivated")
	case inactive.Activated != 0:
		return fmt.Errorf("identity is activated")
	}

	// Update identities
	active := u.ActiveIdentity()
	if active != nil {
		active.Deactivate()
	}
	inactive.Activate()

	return nil
}

// EncodeUser encodes User into a JSON byte slice.
func EncodeUser(u User) ([]byte, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeUser decodes a JSON byte slice into a User.
func DecodeUser(payload []byte) (*User, error) {
	var u User

	err := json.Unmarshal(payload, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// Database interface that is required by the web server.
type Database interface {
	// User functions
	UserGetByUsername(string) (*User, error) // Return user record given the username
	UserGetById(uuid.UUID) (*User, error)    // Return user record given its id
	UserNew(User) error                      // Add new user
	UserUpdate(User) error                   // Update existing user
	AllUsers(callbackFn func(u *User)) error // Iterate all users

	// Close performs cleanup of the backend.
	Close() error
}
