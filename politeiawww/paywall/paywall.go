package paywall

import (
	"errors"

	"github.com/decred/politeia/util/txfetcher"
)

var (
	// ErrDuplicatePaywall is emitted when attempting to register a paywall
	// for an address that already has a paywall registered.
	ErrDuplicatePaywall = errors.New("duplicate paywall")

	// ErrAlreadyPaid is emitted when attempting to register a paywall
	// that has already been paid.
	ErrAlreadyPaid = errors.New("already paid")
)

// Paywall contains the relevant information for a paywall.
type Paywall struct {
	Address     string // Paywall address
	Amount      uint64 // Minimum tx amount required to satisfy paywall
	TxNotBefore int64  // Minimum timestamp for paywall tx
}

// Callback is the signature of the function the paywall Manager calls when a
// payment is received.
type Callback func(Paywall, []txfetcher.TxDetails, bool) error

// Manager is an interface that manages a set of paywalls.
type Manager interface {
	RegisterPaywall(Paywall) error
	RemovePaywall(string)
}
