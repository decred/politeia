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
