package main

import (
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

// ProcessVerifyUserPaymentTx verifies that the provided transaction
// meets the minimum requirements to mark the user as paid, and then does
// that in the user database.
func (b *backend) ProcessVerifyUserPaymentTx(user *database.User, vupt www.VerifyUserPaymentTx) (*www.VerifyUserPaymentTxReply, error) {
	minConfirmations := b.cfg.MinConfirmationsRequired
	verified, err := util.VerifyTxWithBlockExplorers(user.NewUserPaywallAddress,
		user.NewUserPaywallAmount, vupt.TxId, user.NewUserPaywallTxNotBefore, minConfirmations)
	if err != nil {
		return nil, err
	}

	var reply www.VerifyUserPaymentTxReply
	if verified {
		reply.HasPaid = true

		user.NewUserPaywallTx = vupt.TxId
		err = b.db.UserUpdate(*user)
		if err != nil {
			return nil, err
		}
	}

	return &reply, nil
}

// VerifyUserPaid checks that a user has paid the paywall
func (b *backend) VerifyUserPaid(user *database.User) bool {
	// Return true when running unit tests
	if b.test {
		return true
	}

	// Return true if paywall is disabled
	if b.cfg.PaywallAmount == 0 && b.cfg.PaywallXpub == "" {
		return true
	}

	return user.NewUserPaywallTx != ""
}
