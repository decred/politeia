package cockroachdb

import (
	"time"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

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

func (Invoice) TableName() string {
	return tableNameInvoice
}

type LineItem struct {
	LineNumber   uint   `gorm:"not_null"` // LineNumber of each line item
	InvoiceToken string `gorm:"not_null"` // Token of the Invoice that has this lineitem
	Type         string `gorm:"not_null"` // Type of work performed
	Subtype      string `gorm:"not_null"` // Subtype of work performed
	Description  string `gorm:"not_null"` // Description of work performed
	ProposalURL  string `gorm:"not_null"` // Link to politeia proposal that work is associated with
	Hours        uint   `gorm:"not_null"` // Number of Hours
	TotalCost    uint   `gorm:"not_null"` // Total cost of line item
}

func (LineItem) TableName() string {
	return tableNameLineItem
}
