package main

import (
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

type paywallInfo struct {
	address     string
	amount      uint64
	txNotBefore int64
}

const (
	// paywallExpiry is the amount of time the server will watch a paywall address
	// for transactions. It gets reset when the user logs in or makes a call to
	// RouteVerifyUserPayment.
	paywallExpiry = time.Hour * 24

	// paywallCheckGap is the amount of time the server sleeps after polling for
	// a paywall address.
	paywallCheckGap = time.Second * 10
)

func paywallHasExpired(txNotBefore int64) bool {
	expiryTime := time.Unix(txNotBefore, 0).Add(paywallExpiry)
	return time.Now().After(expiryTime)
}

// addUser adds a database user to the paywall pool.
//
// This function must be called WITH the mutex held.
func (b *backend) addUser(user *database.User) {
	b.paywallUsers[user.ID] = paywallInfo{
		address:     user.NewUserPaywallAddress,
		amount:      user.NewUserPaywallAmount,
		txNotBefore: user.NewUserPaywallTxNotBefore,
	}
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

func (b *backend) checkForPayments() {
	// Check new user payments.
	for {
		shouldContinue, userIDsToRemove := b.checkForPaymentsAux()
		if !shouldContinue {
			return
		}
		b.removeUsers(userIDsToRemove)
	}

	// TODO: Check proposal payments within the above loop.
}

func (b *backend) checkForPaymentsAux() (bool, []uint64) {
	var userIDsToRemove []uint64

	b.RLock()
	defer b.RUnlock()

	for userID, paywall := range b.paywallUsers {
		time.Sleep(paywallCheckGap)

		user, err := b.db.UserGetById(userID)
		if err != nil {
			if err == database.ErrShutdown {
				// The database is shutdown, so stop the thread.
				return false, nil
			}

			log.Errorf("cannot fetch user by id %v: %v\n", userID, err)
			continue
		}

		if b.HasUserPaid(user) {
			// The user could have been marked as paid by RouteVerifyUserPayment,
			// so just remove him from the in-memory pool.
			userIDsToRemove = append(userIDsToRemove, userID)
			continue
		}

		if paywallHasExpired(user.NewUserPaywallTxNotBefore) {
			continue
		}

		tx, err := util.FetchTxWithBlockExplorers(paywall.address, paywall.amount,
			paywall.txNotBefore, b.cfg.MinConfirmationsRequired)
		if err != nil {
			log.Errorf("cannot fetch tx: %v\n", err)
			continue
		}

		if tx != "" {
			// Update the user in the database.
			user.NewUserPaywallTx = tx
			err := b.db.UserUpdate(*user)
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
		}
	}

	return true, userIDsToRemove
}

func (b *backend) removeUsers(userIDsToRemove []uint64) {
	b.Lock()
	defer b.Unlock()

	for _, userID := range userIDsToRemove {
		delete(b.paywallUsers, userID)
	}
}

// GenerateNewUserPaywall generates new paywall info, if necessary, and saves
// it in the database.
func (b *backend) GenerateNewUserPaywall(user *database.User) error {
	// Check that the paywall is enabled.
	if !b.PaywallIsEnabled() {
		return nil
	}

	// Check that the user either hasn't had paywall information set yet,
	// or it has expired.
	if user.NewUserPaywallAddress != "" &&
		!paywallHasExpired(user.NewUserPaywallTxNotBefore) {
		return nil
	}

	address, amount, txNotBefore, err := b.derivePaywallInfo(user)
	if err != nil {
		return err
	}

	user.NewUserPaywallAddress = address
	user.NewUserPaywallAmount = amount
	user.NewUserPaywallTxNotBefore = txNotBefore
	err = b.db.UserUpdate(*user)
	if err != nil {
		return err
	}

	b.AddUserToPaywallPool(user)
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

	if paywallHasExpired(user.NewUserPaywallTxNotBefore) {
		b.GenerateNewUserPaywall(user)

		reply.PaywallAddress = user.NewUserPaywallAddress
		reply.PaywallAmount = user.NewUserPaywallAmount
		reply.PaywallTxNotBefore = user.NewUserPaywallTxNotBefore
		return &reply, nil
	}

	txId, err := util.FetchTxWithBlockExplorers(user.NewUserPaywallAddress,
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

	if txId != "" {
		reply.HasPaid = true

		user.NewUserPaywallTx = txId
		err = b.db.UserUpdate(*user)
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
	if !b.PaywallIsEnabled() {
		return true
	}

	return user.NewUserPaywallTx != ""
}

// AddUserToPaywallPool adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) AddUserToPaywallPool(user *database.User) {
	if !b.PaywallIsEnabled() {
		return
	}

	b.Lock()
	defer b.Unlock()

	b.addUser(user)
}

func (b *backend) initPaywallUsersPool() error {
	b.Lock()
	defer b.Unlock()

	if b.paywallUsers == nil {
		b.paywallUsers = make(map[uint64]paywallInfo)
	}

	// Create the in-memory pool of all users who need to pay the paywall.
	return b.db.AllUsers(func(user *database.User) {
		if b.HasUserPaid(user) {
			return
		}
		if user.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(user.NewUserPaywallTxNotBefore) {
			return
		}

		b.addUser(user)
	})
}

// InitPaywallCheck is intended to be called
func (b *backend) InitPaywallCheck() error {
	if b.cfg.PaywallAmount == 0 {
		// Paywall not configured.
		return nil
	}

	err := b.initPaywallUsersPool()
	if err != nil {
		return err
	}

	// Initiate the thread that checks for payments.
	go b.checkForPayments()
	return nil
}

// PaywallIsEnabled returns true if paywall is enabled for the server, false
// otherwise.
func (b *backend) PaywallIsEnabled() bool {
	return b.cfg.PaywallAmount != 0 && b.cfg.PaywallXpub != ""
}
