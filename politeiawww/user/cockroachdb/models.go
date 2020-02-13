package cockroachdb

import (
	"time"

	"github.com/google/uuid"
)

// KeyValue store is a generic key-value store.
type KeyValue struct {
	Key   string `gorm:"primary_key"`
	Value []byte `gorm:"not null"`
}

// TableName returns the table name of the KeyValue table.
func (KeyValue) TableName() string {
	return tableKeyValue
}

// Identity represents a user identity.
type Identity struct {
	PublicKey   string    `gorm:"primary_key;size:64"` // ed25519 public key
	UserID      uuid.UUID `gorm:"not null"`            // User UUID (User foreign key)
	Activated   int64     `gorm:"not null"`            // UNIX timestamp of activation
	Deactivated int64     `gorm:"not null"`            // UNIX timestamp of deactivation
}

// TableName returns the table name of the Identity table.
func (Identity) TableName() string {
	return tableIdentities
}

// User represents a politeiawww user.  Blog is an encrypted blob of the full
// user object.
type User struct {
	ID         uuid.UUID  `gorm:"primary_key"`       // UUID
	Username   string     `gorm:"not null;unique"`   // Unique username
	Identities []Identity `gorm:"foreignkey:UserID"` // User identity history
	Blob       []byte     `gorm:"not null"`          // Encrypted blob of user data

	// Set by gorm
	CreatedAt time.Time // Time of record creation
	UpdatedAt time.Time // Time of last record update
}

// TableName returns the table name of the User table.
func (User) TableName() string {
	return tableUsers
}

// Session represents a user session.
//
// Key is a SHA256 hash of the decoded session ID. The session Store handles
// encoding/decoding the ID.
//
// Blob represents an ecrypted user.Session. The fields that have been broken
// out of the encrypted blob are the fields that need to be queryable.
type Session struct {
	Key       string    `gorm:"primary_key"` // SHA256 hash of the session ID
	UserID    uuid.UUID `gorm:"not null"`    // User UUID
	CreatedAt int64     `gorm:"not null"`    // Created at UNIX timestamp
	Blob      []byte    `gorm:"not null"`    // Encrypted user session
}

// TableName returns the table name of the Session table.
func (Session) TableName() string {
	return tableSessions
}

// CMSUser represents a CMS user. A CMS user includes the politeiawww User
// object as well as CMS specific user fields. A CMS user must correspond to
// a politeiawww User.
//
// This is a CMS plugin model.
//
// XXX We need to update SupervisorUserID to SupervisorUserIDs next time we
// update or do any migration on the userdb.
type CMSUser struct {
	ID                 uuid.UUID `gorm:"primary_key"`            // UUID (User foreign key)
	User               User      `gorm:"not null;foreignkey:ID"` // politeiawww user
	Domain             int       `gorm:"not null"`               // Contractor domain
	GitHubName         string    `gorm:"not null"`               // Github Name/ID
	MatrixName         string    `gorm:"not null"`               // Matrix Name/ID
	ContractorType     int       `gorm:"not null"`               // Type of Contractor
	ContractorName     string    `gorm:"not null"`               // IRL Contractor Name or identity
	ContractorLocation string    `gorm:"not null"`               // General IRL Contractor Location
	ContractorContact  string    `gorm:"not null"`               // Point of contact outside of matrix
	SupervisorUserID   string    `gorm:"not null"`               // This is can either be 1 SupervisorUserID or a comma separated string of many supervisor user ids

	// Set by gorm
	CreatedAt time.Time // Time of record creation
	UpdatedAt time.Time // Time of last record update
}

// TableName returns the table name of the CMSUsers table.
func (CMSUser) TableName() string {
	return tableCMSUsers
}
