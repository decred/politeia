package cockroach

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

// UserEmailHistory represents a history of emails sent to the user with a
// certain email address.
type UserEmailHistory struct {
	ID    uuid.UUID `gorm:"primary_key"`     // UUID
	Email string    `gorm:"not null;unique"` // User email
	// A list of timestamps when an email was sent to this user.
	SentTimestamps []time.Time `gorm:"not null"`
	// Tracks whether a warning email has already been sent to notify the user he exceeded his limit.
	LimitWarningSent bool `gorm:"not null;unique"`

	// Set by gorm
	CreatedAt time.Time // Time of record creation
	UpdatedAt time.Time // Time of last record update
}

// TableName returns the table name of the User table.
func (UserEmailHistory) TableName() string {
	return tableUserEmailHistory
}
