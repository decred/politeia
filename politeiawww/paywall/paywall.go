package paywall

import (
	"errors"

	"github.com/decred/politeia/util/txfetcher"
)

var (
	// ErrDuplicateEntry is emitted when attempting to register a paywall
	// for an address that already has a paywall.
	ErrDuplicateEntry = errors.New("duplicate entry")

	// ErrAlreadyPaid is emitted when attempting to register a paywall
	// that has already been paid.
	ErrAlreadyPaid = errors.New("already paid")
)

// Entry is an entry to a paywall.
type Entry struct {
	Address     string // Paywall address
	Amount      uint64 // Minimum tx amount required to satisfy paywall
	TxNotBefore int64  // Minimum timestamp for paywall tx
}

// Callback is the signature of the function the paywall Manager calls when a
// payment is recieved.
type Callback func(*Entry, []txfetcher.TxDetails, bool) error

// Manager is an interface that manages a set of paywalls.
type Manager interface {
	RegisterPaywall(Entry) error
	RemovePaywall(string)
}
