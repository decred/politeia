package paywall

import (
	"errors"

	"github.com/decred/politeia/util"
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
	id              string           // Used by clients to identify different types of paywalls
	address         string           // Paywall address
	amount          uint64           // Minimum tx amount required to satisfy paywall
	txNotBefore     int64            // Minimum timestamp for paywall tx
}

// Callback is the function the PaywallManager calls when a payment is
// recieved.
type Callback func(*Entry, []util.TxDetails, bool) error

// Manager is an interface that manages a set of paywalls.
type Manager interface {
	RegisterPaywall(*Entry) ([]util.TxDetails, error)
	RemovePaywall(string) error
	SetCallback(Callback)
}
