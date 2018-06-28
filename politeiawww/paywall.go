package main

import (
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

type paywallPoolMember struct {
	address     string
	amount      uint64
	txNotBefore int64
	pollExpiry  int64
}

const (
	// paywallExpiryDuration is the amount of time the server will watch a paywall address
	// for transactions. It gets reset when the user logs in or makes a call to
	// RouteVerifyUserPayment.
	paywallExpiryDuration = time.Hour * 24

	// paywallCheckGap is the amount of time the server sleeps after polling for
	// a paywall address.
	paywallCheckGap = time.Second * 5
)

func paywallHasExpired(pollExpiry int64) bool {
	return time.Now().After(time.Unix(pollExpiry, 0))
}

// paywallIsEnabled returns true if paywall is enabled for the server, false
// otherwise.
func (b *backend) paywallIsEnabled() bool {
	return b.cfg.PaywallAmount != 0 && b.cfg.PaywallXpub != ""
}

// addUserToPaywallPoolWithLock adds a database user to the paywall pool.
//
// This function must be called WITH the mutex held.
func (b *backend) addUserToPaywallPoolWithLock(user *database.User) {
	b.userPaywallPool[user.ID] = paywallPoolMember{
		address:     user.NewUserPaywallAddress,
		amount:      user.NewUserPaywallAmount,
		txNotBefore: user.NewUserPaywallTxNotBefore,
		pollExpiry:  user.NewUserPaywallPollExpiry,
	}
}

// addUserToPaywallPool adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) addUserToPaywallPool(user *database.User) {
	if !b.paywallIsEnabled() {
		return
	}

	b.Lock()
	defer b.Unlock()

	b.addUserToPaywallPoolWithLock(user)
}

func (b *backend) updateUserAsPaid(user *database.User, tx string) error {
	user.NewUserPaywallTx = tx
	user.NewUserPaywallPollExpiry = 0
	return b.db.UserUpdate(*user)
}

func (b *backend) derivePaywallInfo(user *database.User) (string, uint64, int64, error) {
	address, err := util.DerivePaywallAddress(b.params,
		b.cfg.PaywallXpub, uint32(user.ID))
	if err != nil {
		err = fmt.Errorf("Unable to derive paywall address #%v "+
			"for %v: %v", uint32(user.ID), user.Email, err)
	}

	return address, b.cfg.PaywallAmount, time.Now().Unix(), err
}

func (b *backend) createUserPaywallPoolCopy() map[uint64]paywallPoolMember {
	b.RLock()
	defer b.RUnlock()

	copy := make(map[uint64]paywallPoolMember, len(b.userPaywallPool))

	for k, v := range b.userPaywallPool {
		copy[k] = v
	}

	return copy
}

func (b *backend) checkForUserPayments(pool map[uint64]paywallPoolMember) (bool, []uint64) {
	var userIDsToRemove []uint64

	for userID, poolMember := range pool {
		user, err := b.db.UserGetById(userID)
		if err != nil {
			if err == database.ErrShutdown {
				// The database is shutdown, so stop the thread.
				return false, nil
			}

			log.Errorf("cannot fetch user by id %v: %v\n", userID, err)
			continue
		}

		log.Tracef("Checking the paywall address for user %v...", user.Email)

		if b.HasUserPaid(user) {
			// The user could have been marked as paid by RouteVerifyUserPayment,
			// so just remove him from the in-memory pool.
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user already paid")
			continue
		}

		if paywallHasExpired(user.NewUserPaywallPollExpiry) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, poll has expired")
			continue
		}

		tx, err := util.FetchTxWithBlockExplorers(poolMember.address, poolMember.amount,
			poolMember.txNotBefore, b.cfg.MinConfirmationsRequired)
		if err != nil {
			log.Errorf("cannot fetch tx: %v\n", err)
			continue
		}

		if tx != "" {
			// Update the user in the database.
			err = b.updateUserAsPaid(user, tx)
			if err != nil {
				if err == database.ErrShutdown {
					// The database is shutdown, so stop the thread.
					return false, nil
				}

				log.Errorf("cannot update user with id %v: %v", user.ID, err)
				continue
			}

			// Remove this user from the in-memory pool.
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user just paid")
		}

		time.Sleep(paywallCheckGap)
	}

	return true, userIDsToRemove
}

func (b *backend) removeUsersFromPool(userIDsToRemove []uint64) {
	b.Lock()
	defer b.Unlock()

	for _, userID := range userIDsToRemove {
		delete(b.userPaywallPool, userID)
	}
}

func (b *backend) checkForPayments() {
	for {
		// Check new user payments.
		userPaywallsToCheck := b.createUserPaywallPoolCopy()
		shouldContinue, userIDsToRemove := b.checkForUserPayments(userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		b.removeUsersFromPool(userIDsToRemove)

		// TODO: Check for proposal payments.
	}
}

// GenerateNewUserPaywall generates new paywall info, if necessary, and saves
// it in the database.
func (b *backend) GenerateNewUserPaywall(user *database.User) error {
	// Check that the paywall is enabled.
	if !b.paywallIsEnabled() {
		return nil
	}

	// Check that the user either hasn't had paywall information set yet,
	// or it has expired.
	if user.NewUserPaywallAddress != "" &&
		!paywallHasExpired(user.NewUserPaywallPollExpiry) {
		return nil
	}

	if user.NewUserPaywallAddress == "" {
		address, amount, txNotBefore, err := b.derivePaywallInfo(user)
		if err != nil {
			return err
		}

		user.NewUserPaywallAddress = address
		user.NewUserPaywallAmount = amount
		user.NewUserPaywallTxNotBefore = txNotBefore
	}
	user.NewUserPaywallPollExpiry = time.Now().Add(paywallExpiryDuration).Unix()

	err := b.db.UserUpdate(*user)
	if err != nil {
		return err
	}

	b.addUserToPaywallPool(user)
	return nil
}

// ProcessVerifyUserPayment verifies that the provided transaction
// meets the minimum requirements to mark the user as paid, and then does
// that in the user database.
func (b *backend) ProcessVerifyUserPayment(user *database.User, vupt v1.VerifyUserPayment) (*v1.VerifyUserPaymentReply, error) {
	var reply v1.VerifyUserPaymentReply
	if b.HasUserPaid(user) {
		reply.HasPaid = true
		return &reply, nil
	}

	if paywallHasExpired(user.NewUserPaywallPollExpiry) {
		b.GenerateNewUserPaywall(user)

		reply.PaywallAddress = user.NewUserPaywallAddress
		reply.PaywallAmount = user.NewUserPaywallAmount
		reply.PaywallTxNotBefore = user.NewUserPaywallTxNotBefore
		return &reply, nil
	}

	tx, err := util.FetchTxWithBlockExplorers(user.NewUserPaywallAddress,
		user.NewUserPaywallAmount, user.NewUserPaywallTxNotBefore,
		b.cfg.MinConfirmationsRequired)
	if err != nil {
		if err == util.ErrCannotVerifyPayment {
			return nil, v1.UserError{
				ErrorCode: v1.ErrorStatusCannotVerifyPayment,
			}
		}
		return nil, err
	}

	if tx != "" {
		reply.HasPaid = true

		err = b.updateUserAsPaid(user, tx)
		if err != nil {
			return nil, err
		}
	} else {
		// Add the user to the in-memory pool.
	}

	return &reply, nil
}

// HasUserPaid checks that a user has paid the paywall
func (b *backend) HasUserPaid(user *database.User) bool {
	// Return true when running unit tests
	if b.test {
		return true
	}

	// Return true if paywall is disabled
	if !b.paywallIsEnabled() {
		return true
	}

	return user.NewUserPaywallTx != ""
}

func (b *backend) addUsersToPaywallPool() error {
	b.Lock()
	defer b.Unlock()

	// Create the in-memory pool of all users who need to pay the paywall.
	err := b.db.AllUsers(func(user *database.User) {
		if b.HasUserPaid(user) {
			return
		}
		if user.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(user.NewUserPaywallPollExpiry) {
			return
		}

		b.addUserToPaywallPoolWithLock(user)
	})
	if err != nil {
		return err
	}

	log.Tracef("Adding %v users to paywall pool", len(b.userPaywallPool))
	return nil
}

// initPaywallCheck is intended to be called
func (b *backend) initPaywallChecker() error {
	if b.cfg.PaywallAmount == 0 {
		// Paywall not configured.
		return nil
	}

	err := b.addUsersToPaywallPool()
	if err != nil {
		return err
	}

	// Start the thread that checks for payments.
	go b.checkForPayments()
	return nil
}
