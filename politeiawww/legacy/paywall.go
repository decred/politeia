// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

type paywallPoolMember struct {
	paywallType     string // Used to differentiate between user and proposal paywalls
	address         string // Paywall address
	amount          uint64 // Minimum tx amount required to satisfy paywall
	txNotBefore     int64  // Minimum timestamp for paywall tx
	pollExpiry      int64  // After this time, the paywall address will not be continuously polled
	txID            string // ID of the pending payment tx
	txAmount        uint64 // Amount of the pending payment tx
	txConfirmations uint64 // Number of confirmations of the pending payment tx
}

const (
	// paywallExpiryDuration is the amount of time the server will watch a paywall address
	// for transactions. It gets reset when the user logs in or makes a call to
	// RouteUserRegistrationPayment.
	paywallExpiryDuration = time.Hour * 24

	// paywallCheckGap is the amount of time the server sleeps after polling for
	// a paywall address.
	paywallCheckGap = time.Second * 1

	// paywallTypeUser and paywallTypeProposal are used to signify whether a
	// paywall pool member is a user registration fee paywall or a proposal
	// credit paywall. Different actions are taken by the paywall pool depending
	// on the paywall type.
	paywallTypeUser     = "user"
	paywallTypeProposal = "proposal"
)

func paywallHasExpired(pollExpiry int64) bool {
	return time.Now().After(time.Unix(pollExpiry, 0))
}

// paywallIsEnabled returns true if paywall is enabled for the server, false
// otherwise.
func (p *Politeiawww) paywallIsEnabled() bool {
	return p.cfg.PaywallAmount != 0 && p.cfg.PaywallXpub != ""
}

// initPaywallCheck is intended to be called
func (p *Politeiawww) initPaywallChecker() error {
	if p.cfg.PaywallAmount == 0 {
		// Paywall not configured.
		return nil
	}

	err := p.addUsersToPaywallPool()
	if err != nil {
		return err
	}

	// Start the thread that checks for payments.
	go p.checkForPayments()
	return nil
}

// checkForProposalPayments checks if any of the proposal paywalls in the
// paywall pool have received a payment.  If so, proposal credits are created
// for the user, the user database is updated, and the user is removed from
// the paywall pool.
func (p *Politeiawww) checkForProposalPayments(ctx context.Context, pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

	// In theory poolMember could be raced during this call. In practice
	// a race will not occur as long as the paywall does not remove
	// poolMembers from the pool while in the middle of polling poolMember
	// addresses.
	for userID, poolMember := range pool {
		u, err := p.db.UserGetById(userID)
		if err != nil {
			if errors.Is(err, user.ErrShutdown) {
				// The database is shutdown, so stop the thread.
				return false, nil
			}

			log.Errorf("cannot fetch user by id %v: %v\n", userID, err)
			continue
		}

		if poolMember.paywallType != paywallTypeProposal {
			continue
		}

		log.Tracef("Checking proposal paywall address for user %v...", u.Email)

		paywall := p.mostRecentProposalPaywall(u)

		// Sanity check
		if paywall == nil {
			continue
		}

		if paywallHasExpired(paywall.PollExpiry) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, poll has expired")
			continue
		}

		tx, err := p.verifyProposalPayment(ctx, u)
		if err != nil {
			if errors.Is(err, user.ErrShutdown) {
				// The database is shutdown, so stop the thread.
				return false, nil
			}

			log.Errorf("cannot update user with id %v: %v", u.ID, err)
			continue
		}

		// Removed paywall from the in-memory pool if it has
		// been marked as paid.
		if !p.userHasValidProposalPaywall(u) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user just paid")
		} else if tx != nil {
			log.Tracef("  updating pool member with id: %v", userID)

			// Update pool member if payment tx was found but
			// does not have enough confimrations.
			poolMember.txID = tx.TxID
			poolMember.txAmount = tx.Amount
			poolMember.txConfirmations = tx.Confirmations

			p.Lock()
			p.userPaywallPool[userID] = poolMember
			p.Unlock()
		}

		time.Sleep(paywallCheckGap)
	}

	return true, userIDsToRemove
}

func (p *Politeiawww) checkForPayments() {
	ctx := context.Background()
	for {
		// Removing pool members from the pool while in the middle of
		// polling can cause a race to occur in checkForProposalPayments.
		userPaywallsToCheck := p.createUserPaywallPoolCopy()

		// Check new user payments.
		shouldContinue, userIDsToRemove := p.checkForUserPayments(ctx, userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		p.removeUsersFromPool(userIDsToRemove, paywallTypeUser)

		// Check proposal payments.
		shouldContinue, userIDsToRemove = p.checkForProposalPayments(ctx, userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		p.removeUsersFromPool(userIDsToRemove, paywallTypeProposal)

		time.Sleep(paywallCheckGap)
	}
}

// generateNewUserPaywall generates new paywall info, if necessary, and saves
// it in the database.
func (p *Politeiawww) generateNewUserPaywall(u *user.User) error {
	// Check that the paywall is enabled.
	if !p.paywallIsEnabled() {
		return nil
	}

	// Check that the user either hasn't had paywall information set yet,
	// or it has expired.
	if u.NewUserPaywallAddress != "" &&
		!paywallHasExpired(u.NewUserPaywallPollExpiry) {
		return nil
	}

	if u.NewUserPaywallAddress == "" {
		address, amount, txNotBefore, err := p.derivePaywallInfo(u)
		if err != nil {
			return err
		}

		u.NewUserPaywallAddress = address
		u.NewUserPaywallAmount = amount
		u.NewUserPaywallTxNotBefore = txNotBefore
	}
	u.NewUserPaywallPollExpiry = time.Now().Add(paywallExpiryDuration).Unix()

	err := p.db.UserUpdate(*u)
	if err != nil {
		return err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeUser)
	return nil
}

// mostRecentProposalPaywall returns the most recent paywall that has been
// issued to the user.  Just because a paywall is the most recent paywall does
// not guarantee that it is still valid.  Depending on the circumstances, the
// paywall could have already been paid, could have already expired, or could
// still be valid.
func (p *Politeiawww) mostRecentProposalPaywall(user *user.User) *user.ProposalPaywall {
	if len(user.ProposalPaywalls) > 0 {
		return &user.ProposalPaywalls[len(user.ProposalPaywalls)-1]
	}
	return nil
}

// userHasValidProposalPaywall checks if the user has been issued a paywall
// that has not been paid yet and that has not expired yet.  Only one paywall
// per user can be valid at a time, so if a valid paywall exists for the user,
// it will be the most recent paywall.
func (p *Politeiawww) userHasValidProposalPaywall(user *user.User) bool {
	pp := p.mostRecentProposalPaywall(user)
	return pp != nil && pp.TxID == "" && !paywallHasExpired(pp.PollExpiry)
}

// generateProposalPaywall creates a new proposal paywall for the user that
// enables them to purchase proposal credits.  Once the paywall is created, the
// user database is updated and the user is added to the paywall pool.
func (p *Politeiawww) generateProposalPaywall(u *user.User) (*user.ProposalPaywall, error) {
	address, amount, txNotBefore, err := p.derivePaywallInfo(u)
	if err != nil {
		return nil, err
	}
	pp := user.ProposalPaywall{
		ID:          uint64(len(u.ProposalPaywalls) + 1),
		CreditPrice: amount,
		Address:     address,
		TxNotBefore: txNotBefore,
		PollExpiry:  time.Now().Add(paywallExpiryDuration).Unix(),
	}
	u.ProposalPaywalls = append(u.ProposalPaywalls, pp)

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeProposal)
	return &pp, nil
}

// verifyPropoposalPayment checks whether a payment has been sent to the
// user's proposal paywall address. Proposal credits are created and added to
// the user's account if the payment meets the minimum requirements.
func (p *Politeiawww) verifyProposalPayment(ctx context.Context, u *user.User) (*TxDetails, error) {
	paywall := p.mostRecentProposalPaywall(u)

	// If a TxID exists, the payment has already been verified.
	if paywall.TxID != "" {
		return nil, nil
	}

	// Fetch txs sent to paywall address
	txs, err := fetchTxsForAddress(ctx, p.params, paywall.Address,
		p.dcrdataHostHTTP())
	if err != nil {
		return nil, fmt.Errorf("FetchTxsForAddress %v: %v",
			paywall.Address, err)
	}

	// Check for paywall payment tx
	for _, tx := range txs {
		switch {
		case tx.Timestamp < paywall.TxNotBefore && tx.Timestamp != 0:
			continue
		case tx.Amount < paywall.CreditPrice:
			continue
		case tx.Confirmations < p.cfg.MinConfirmationsRequired:
			// Payment tx found but not enough confirmations. Return
			// the tx so that the paywall member can be updated.
			return &tx, nil
		default:
			// Payment tx found that meets all criteria. Create
			// proposal credits and update user db record.
			paywall.TxID = tx.TxID
			paywall.TxAmount = tx.Amount
			paywall.NumCredits = tx.Amount / paywall.CreditPrice

			// Create proposal credits
			c := make([]user.ProposalCredit, paywall.NumCredits)
			timestamp := time.Now().Unix()
			for i := uint64(0); i < paywall.NumCredits; i++ {
				c[i] = user.ProposalCredit{
					PaywallID:     paywall.ID,
					Price:         paywall.CreditPrice,
					DatePurchased: timestamp,
					TxID:          paywall.TxID,
				}
			}
			u.UnspentProposalCredits = append(u.UnspentProposalCredits, c...)

			// Update user database.
			err = p.db.UserUpdate(*u)
			if err != nil {
				return nil, fmt.Errorf("database UserUpdate: %v", err)
			}

			return &tx, nil
		}
	}

	return nil, nil
}

// removeUsersFromPool removes the provided user IDs from the the poll pool.
//
// Currently, updating the user db and removing the user from pool isn't an
// atomic operation.  This can lead to a scenario where the user has been
// marked as paid in the db, but has not yet been removed from the pool. If a
// user issues a proposal paywall during this time, the proposal paywall will
// replace the user paywall in the pool. When the pool proceeds to remove the
// user paywall, it will mistakenly remove the proposal paywall instead.
// Proposal credits will not be added to the user's account. The workaround
// until this code gets replaced with websockets is to pass in the paywallType
// when removing a pool member.
//
// This function must be called WITHOUT the mutex held.
func (p *Politeiawww) removeUsersFromPool(userIDsToRemove []uuid.UUID, paywallType string) {
	p.Lock()
	defer p.Unlock()

	for _, userID := range userIDsToRemove {
		if p.userPaywallPool[userID].paywallType == paywallType {
			delete(p.userPaywallPool, userID)
		}
	}
}

// addUserToPaywallPool adds a database user to the paywall pool.
//
// This function must be called WITH the mutex held.
func (p *Politeiawww) addUserToPaywallPool(u *user.User, paywallType string) {
	p.userPaywallPool[u.ID] = paywallPoolMember{
		paywallType: paywallType,
		address:     u.NewUserPaywallAddress,
		amount:      u.NewUserPaywallAmount,
		txNotBefore: u.NewUserPaywallTxNotBefore,
		pollExpiry:  u.NewUserPaywallPollExpiry,
	}
}

// addUserToPaywallPoolLock adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (p *Politeiawww) addUserToPaywallPoolLock(u *user.User, paywallType string) {
	if !p.paywallIsEnabled() {
		return
	}

	p.Lock()
	defer p.Unlock()

	p.addUserToPaywallPool(u, paywallType)
}

// addUsersToPaywallPool adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (p *Politeiawww) addUsersToPaywallPool() error {
	p.Lock()
	defer p.Unlock()

	// Create the in-memory pool of all users who need to pay the paywall.
	err := p.db.AllUsers(func(u *user.User) {
		// Proposal paywalls
		if p.userHasValidProposalPaywall(u) {
			p.addUserToPaywallPool(u, paywallTypeProposal)
			return
		}

		// User paywalls
		if p.userHasPaid(*u) {
			return
		}
		if u.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(u.NewUserPaywallPollExpiry) {
			return
		}

		p.addUserToPaywallPool(u, paywallTypeUser)
	})
	if err != nil {
		return err
	}

	log.Tracef("Adding %v users to paywall pool", len(p.userPaywallPool))
	return nil
}

// updateUserAsPaid records in the database that the user has paid.
func (p *Politeiawww) updateUserAsPaid(u *user.User, tx string) error {
	u.NewUserPaywallTx = tx
	u.NewUserPaywallPollExpiry = 0
	return p.db.UserUpdate(*u)
}

// derivePaywallInfo derives a new paywall address for the user.
func (p *Politeiawww) derivePaywallInfo(u *user.User) (string, uint64, int64, error) {
	address, err := util.DeriveChildAddress(p.params,
		p.cfg.PaywallXpub, uint32(u.PaywallAddressIndex))
	if err != nil {
		err = fmt.Errorf("Unable to derive paywall address #%v "+
			"for %v: %v", u.ID.ID(), u.Email, err)
	}

	return address, p.cfg.PaywallAmount, time.Now().Unix(), err
}

// createUserPaywallPoolCopy returns a map of the poll pool.
//
// This function must be called WITHOUT the mutex held.
func (p *Politeiawww) createUserPaywallPoolCopy() map[uuid.UUID]paywallPoolMember {
	p.RLock()
	defer p.RUnlock()

	poolCopy := make(map[uuid.UUID]paywallPoolMember, len(p.userPaywallPool))

	for k, v := range p.userPaywallPool {
		poolCopy[k] = v
	}

	return poolCopy
}

// checkForUserPayments is called periodically to see if payments have come
// through.
func (p *Politeiawww) checkForUserPayments(ctx context.Context, pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

	for userID, poolMember := range pool {
		u, err := p.db.UserGetById(userID)
		if err != nil {
			if errors.Is(err, user.ErrShutdown) {
				// The database is shutdown, so stop the
				// thread.
				return false, nil
			}

			log.Errorf("cannot fetch user by id %v: %v\n",
				userID, err)
			continue
		}

		if poolMember.paywallType != paywallTypeUser {
			continue
		}

		log.Tracef("Checking the user paywall address for user %v...",
			u.Email)

		if p.userHasPaid(*u) {
			// The user could have been marked as paid by
			// RouteUserRegistrationPayment, so just remove him from the
			// in-memory pool.
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user already paid")
			continue
		}

		if paywallHasExpired(u.NewUserPaywallPollExpiry) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, poll has expired")
			continue
		}

		tx, _, err := fetchTxWithBlockExplorers(ctx, p.params, poolMember.address,
			poolMember.amount, poolMember.txNotBefore,
			p.cfg.MinConfirmationsRequired, p.dcrdataHostHTTP())
		if err != nil {
			log.Errorf("cannot fetch tx: %v\n", err)
			continue
		}

		if tx != "" {
			// Update the user in the database.
			err = p.updateUserAsPaid(u, tx)
			if err != nil {
				if errors.Is(err, user.ErrShutdown) {
					// The database is shutdown, so stop
					// the thread.
					return false, nil
				}

				log.Errorf("cannot update user with id %v: %v",
					u.ID, err)
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

// userHasPaid returns whether the user has paid the user registration paywall.
func (p *Politeiawww) userHasPaid(u user.User) bool {
	if !p.paywallIsEnabled() {
		return true
	}
	return u.NewUserPaywallTx != ""
}
