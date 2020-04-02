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

	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/google/uuid"
)

var (
	// ErrSessionNotFound indicates that a user session was not found
	// in the database.
	ErrSessionNotFound = errors.New("no user session found")

	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates that a user already exists in the
	// database.
	ErrUserExists = errors.New("user already exists")

	// ErrShutdown is emitted when the database is shutting down.
	ErrShutdown = errors.New("database is shutting down")

	// ErrInvalidPlugin is emitted when a invalid plugin is used.
	ErrInvalidPlugin = errors.New("invalid plugin")

	// ErrInvalidPluginCmd is emitted when an invalid plugin command
	// is used.
	ErrInvalidPluginCmd = errors.New("invalid plugin command")
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
	Key         [identity.PublicKeySize]byte `json:"key"`         // ed25519 public key
	Activated   int64                        `json:"activated"`   // Time key as activated for use
	Deactivated int64                        `json:"deactivated"` // Time key was deactivated
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
	ID          uint64 `json:"id"`          // Paywall ID
	CreditPrice uint64 `json:"creditprice"` // Cost per proposal credit in atoms
	Address     string `json:"address"`     // Paywall address
	TxNotBefore int64  `json:"txnotbefore"` // Unix timestamp of minimum timestamp for paywall tx
	PollExpiry  int64  `json:"pollexpiry"`  // Unix timestamp of expiration time of paywall polling
	TxID        string `json:"txid"`        // Payment transaction ID
	TxAmount    uint64 `json:"txamount"`    // Amount sent to paywall address in atoms
	NumCredits  uint64 `json:"numcredits"`  // Number of proposal credits created by payment tx
}

// A proposal credit allows the user to submit a new proposal.  Credits are
// created when a user sends a payment to a proposal paywall.  A credit is
// automatically spent when a user submits a new proposal.  When a credit is
// spent, it is updated with the proposal's censorship token and moved to the
// user's spent proposal credits list.
type ProposalCredit struct {
	PaywallID       uint64 `json:"paywallid"`       // Proposal paywall ID of associated paywall
	Price           uint64 `json:"price"`           // Credit price in atoms
	DatePurchased   int64  `json:"datepurchased"`   // Unix timestamp of credit purchase
	TxID            string `json:"txid"`            // Payment transaction ID
	CensorshipToken string `json:"censorshiptoken"` // Token of proposal that spent this credit
}

// VersionUser is the version of the User struct.
const VersionUser uint32 = 1

// User represents a politeiawww user.
type User struct {
	ID                  uuid.UUID `json:"id"`                  // Unique user uuid
	Email               string    `json:"email"`               // Email address
	Username            string    `json:"username"`            // Unique username
	HashedPassword      []byte    `json:"hashedpassword"`      // Blowfish hash
	Admin               bool      `json:"admin"`               // Is user an admin
	EmailNotifications  uint64    `json:"emailnotifications"`  // Email notification setting
	LastLoginTime       int64     `json:"lastlogintime"`       // Unix timestamp of last login
	FailedLoginAttempts uint64    `json:"failedloginattempts"` // Sequential failed login attempts
	Deactivated         bool      `json:"deactivated"`         // Is account deactivated

	// Verification tokens and their expirations
	NewUserVerificationToken        []byte `json:"newuserverificationtoken"`
	NewUserVerificationExpiry       int64  `json:"newuserverificationtokenexiry"`
	ResendNewUserVerificationExpiry int64  `json:"resendnewuserverificationtoken"`
	UpdateKeyVerificationToken      []byte `json:"updatekeyverificationtoken"`
	UpdateKeyVerificationExpiry     int64  `json:"updatekeyverificationexpiry"`
	ResetPasswordVerificationToken  []byte `json:"resetpasswordverificationtoken"`
	ResetPasswordVerificationExpiry int64  `json:"resetpasswordverificationexpiry"`

	// PaywallAddressIndex is the index that is used to generate the
	// paywall address for the user. The same paywall address is used
	// for the user registration paywall and for proposal credit
	// paywalls. The index is set during the new user record creation
	// and is sequential.
	// XXX why is this an uint64 when hdkeychain requires a uint32?
	PaywallAddressIndex uint64 `json:"paywalladdressindex"`

	// User registration paywall info
	NewUserPaywallAddress string `json:"newuserpaywalladdress"`
	NewUserPaywallAmount  uint64 `json:"newuserpaywallamount"`
	NewUserPaywallTx      string `json:"newuserpaywalltx"`

	// NewUserPaywallTxNotBeore is the minimum UNIX time (in seconds)
	// required for the block containing the transaction sent to
	// NewUserPaywallAddress. If the user has already paid, this field
	// will be empty.
	NewUserPaywallTxNotBefore int64 `json:"newuserpaywalltxnotbefore"`

	// The UNIX time (in seconds) for when the server will stop polling
	// the server for transactions at NewUserPaywallAddress. If the
	// user has already paid, this field will be empty.
	NewUserPaywallPollExpiry int64 `json:"newuserpaywallpollexpiry"`

	// User access times for proposal comments. The access time is a
	// Unix timestamp of the last time the user accessed a proposal's
	// comments.
	// [token]accessTime
	ProposalCommentsAccessTimes map[string]int64 `json:"proposalcommentsaccesstime"`

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
	Identities []Identity `json:"identities"`

	// All proposal paywalls that have been issued to the user in chronological
	// order.
	ProposalPaywalls []ProposalPaywall `json:"proposalpaywalls"`

	// All proposal credits that have been purchased by the user, but have not
	// yet been used to submit a proposal.  Once a credit is used to submit a
	// proposal, it is updated with the proposal's censorship token and moved to
	// the user's spent proposal credits list.  The price that the proposal
	// credit was purchased at is in atoms.
	UnspentProposalCredits []ProposalCredit `json:"unspentproposalcredits"`

	// All credits that have been purchased by the user and have already been
	// used to submit proposals.  Spent credits have a proposal censorship token
	// associated with them to signify that they have been spent. The price that
	// the proposal credit was purchased at is in atoms.
	SpentProposalCredits []ProposalCredit `json:"spentproposalcredits"`
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

// PublicKey returns a hex encoded string of the user's active identity.
func (u *User) PublicKey() string {
	if u.ActiveIdentity() != nil {
		return u.ActiveIdentity().String()
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

	// Deactivate any active identities. There should only ever be a
	// single active identity at a time, but due to a prior bug in the
	// early version of politeia, this may not hold true. Check all
	// identities just to be sure.
	for k, v := range u.Identities {
		// Skip the inactive identity that is going
		// to be the new active identity.
		if inactive.String() == v.String() {
			continue
		}

		if v.Deactivated == 0 {
			u.Identities[k].Deactivate()
		}
	}

	// Update the inactive identity to be active.
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

// PluginCommand is used to execute a plugin command.
type PluginCommand struct {
	ID      string // Plugin identifier
	Command string // Command identifier
	Payload string // Command payload
}

// PluginCommandReply is used to reply to a PluginCommand.
type PluginCommandReply struct {
	ID      string // Plugin identifier
	Command string // Command identifier
	Payload string // Command reply payload
}

// PluginSetting holds the key/value pair of a plugin setting.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string
	Version  string
	Settings []PluginSetting
}

// Session represents a user session.
//
// ID is the decoded session ID. The ID present in the session cookie is the
// encoded session ID. The encoding/decoding is handled by the session Store.
//
// Values are politeiawww specific encoded session values. The encoding is
// handled by the session Store.
//
// UserID and CreatedAt are included in the encoded Values but have also been
// broken out into their own fields so that they can be queryable. UserID
// allows for lookups by UserID and CreatedAt allows for periodically cleaning
// up expired sessions in the database.
type Session struct {
	ID        string    `json:"id"`        // Unique session ID
	UserID    uuid.UUID `json:"userid"`    // User UUID
	CreatedAt int64     `json:"createdat"` // Created at UNIX timestamp
	Values    string    `json:"values"`    // Encoded session values
}

// VersionSession is the version of the Session struct.
const VersionSession uint32 = 1

// EncodeSession encodes Session into a JSON byte slice.
func EncodeSession(s Session) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeSession decodes a JSON byte slice into a Session.
func DecodeSession(payload []byte) (*Session, error) {
	var s Session

	err := json.Unmarshal(payload, &s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// Database describes the interface used for interacting with the user
// database.
type Database interface {
	// Add a new user
	UserNew(User) error

	// Update an existing user
	UserUpdate(User) error

	// Return user record given the username
	UserGetByUsername(string) (*User, error)

	// Return user record given its id
	UserGetById(uuid.UUID) (*User, error)

	// Return user record given a public key
	UserGetByPubKey(string) (*User, error)

	// Return a map of public key to user record
	UsersGetByPubKey(pubKeys []string) (map[string]User, error)

	// Iterate over all users
	AllUsers(callbackFn func(u *User)) error

	// Create or update a user session
	SessionSave(Session) error

	// Return a user session given its id
	SessionGetByID(sessionID string) (*Session, error)

	// Delete a user session given its id
	SessionDeleteByID(sessionID string) error

	// Delete all sessions for a user except for the given session IDs
	SessionsDeleteByUserID(id uuid.UUID, exemptSessionIDs []string) error

	// Register a plugin
	RegisterPlugin(Plugin) error

	// Execute a plugin command
	PluginExec(PluginCommand) (*PluginCommandReply, error)

	// Close performs cleanup of the backend.
	Close() error
}
