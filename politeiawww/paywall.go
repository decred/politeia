package main

import (
	"fmt"
	"sync"
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
	paywallCheckGap = time.Second * 1
)

var (
	paywallUsers map[uint64]paywallInfo
	mutex        sync.RWMutex
)

func paywallHasExpired(txNotBefore int64) bool {
	expiryTime := time.Unix(txNotBefore, 0).Add(paywallExpiry)
	return time.Now().After(expiryTime)
}

func addUser(user *database.User) {
	paywallUsers[user.ID] = paywallInfo{
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
	minConfirmations := b.cfg.MinConfirmationsRequired

	// Check new user payments.
	for {
		var userIdsToRemove []uint64

		mutex.RLock()
		for userId, paywall := range paywallUsers {
			user, err := b.db.UserGetById(userId)
			if err != nil {
				log.Errorf("cannot fetch user by id %v: %v\n", userId, err)
				continue
			}

			if b.HasUserPaid(user) {
				// The user could have been marked as paid by RouteVerifyUserPayment,
				// so just remove him from the in-memory pool.
				userIdsToRemove = append(userIdsToRemove, userId)
				continue
			}

			if paywallHasExpired(user.NewUserPaywallTxNotBefore) {
				continue
			}

			tx, err := util.FetchTxWithBlockExplorers(paywall.address, paywall.amount,
				paywall.txNotBefore, minConfirmations)
			if err != nil {
				log.Errorf("cannot fetch tx: %v\n", err)
				continue
			}

			if tx != "" {
				// Update the user in the database.
				user.NewUserPaywallTx = tx
				err := b.db.UserUpdate(*user)
				if err != nil {
					log.Errorf("cannot update user with id %v: %v", user.ID, err)
					continue
				}

				// Remove this user from the in-memory pool.
				userIdsToRemove = append(userIdsToRemove, userId)
			}

			time.Sleep(paywallCheckGap)
		}
		mutex.RUnlock()

		mutex.Lock()
		for _, userId := range userIdsToRemove {
			delete(paywallUsers, userId)
		}
		mutex.Unlock()
	}

	// TODO: Check proposal payments within the above loop.
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

	minConfirmations := b.cfg.MinConfirmationsRequired
	txId, err := util.FetchTxWithBlockExplorers(user.NewUserPaywallAddress,
		user.NewUserPaywallAmount, user.NewUserPaywallTxNotBefore, minConfirmations)
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
func (b *backend) AddUserToPaywallPool(user *database.User) {
	mutex.Lock()
	addUser(user)
	mutex.Unlock()
}

// InitPaywallCheck is intended to be called
func (b *backend) InitPaywallCheck() error {
	if b.cfg.PaywallAmount == 0 {
		// Paywall not configured.
		return nil
	}

	paywallUsers = make(map[uint64]paywallInfo)

	// Create the in-memory pool of all users who need to pay the paywall.
	mutex.Lock()
	err := b.db.AllUsers(func(user *database.User) {
		if b.HasUserPaid(user) {
			return
		}
		if user.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(user.NewUserPaywallTxNotBefore) {
			return
		}

		addUser(user)
	})
	mutex.Unlock()

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
