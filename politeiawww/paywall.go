// Copyright (c) 2018-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/thi4go/politeia/util"
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
	// RouteVerifyUserPayment.
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
func (p *politeiawww) paywallIsEnabled() bool {
	return p.cfg.PaywallAmount != 0 && p.cfg.PaywallXpub != ""
}

// checkForProposalPayments checks if any of the proposal paywalls in the
// paywall pool have received a payment.  If so, proposal credits are created
// for the user, the user database is updated, and the user is removed from
// the paywall pool.
func (p *politeiawww) checkForProposalPayments(pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

	// In theory poolMember could be raced during this call. In practice
	// a race will not occur as long as the paywall does not remove
	// poolMembers from the pool while in the middle of polling poolMember
	// addresses.
	for userID, poolMember := range pool {
		u, err := p.db.UserGetById(userID)
		if err != nil {
			if err == user.ErrShutdown {
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

		tx, err := p.verifyProposalPayment(u)
		if err != nil {
			if err == user.ErrShutdown {
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

func (p *politeiawww) checkForPayments() {
	for {
		// Removing pool members from the pool while in the middle of
		// polling can cause a race to occur in checkForProposalPayments.
		userPaywallsToCheck := p.createUserPaywallPoolCopy()

		// Check new user payments.
		shouldContinue, userIDsToRemove := p.checkForUserPayments(userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		p.removeUsersFromPool(userIDsToRemove, paywallTypeUser)

		// Check proposal payments.
		shouldContinue, userIDsToRemove = p.checkForProposalPayments(userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		p.removeUsersFromPool(userIDsToRemove, paywallTypeProposal)

		time.Sleep(paywallCheckGap)
	}
}

// mostRecentProposalPaywall returns the most recent paywall that has been
// issued to the user.  Just because a paywall is the most recent paywall does
// not guarantee that it is still valid.  Depending on the circumstances, the
// paywall could have already been paid, could have already expired, or could
// still be valid.
func (p *politeiawww) mostRecentProposalPaywall(user *user.User) *user.ProposalPaywall {
	if len(user.ProposalPaywalls) > 0 {
		return &user.ProposalPaywalls[len(user.ProposalPaywalls)-1]
	}
	return nil
}

// userHasValidProposalPaywall checks if the user has been issued a paywall
// that has not been paid yet and that has not expired yet.  Only one paywall
// per user can be valid at a time, so if a valid paywall exists for the user,
// it will be the most recent paywall.
func (p *politeiawww) userHasValidProposalPaywall(user *user.User) bool {
	pp := p.mostRecentProposalPaywall(user)
	return pp != nil && pp.TxID == "" && !paywallHasExpired(pp.PollExpiry)
}

// generateProposalPaywall creates a new proposal paywall for the user that
// enables them to purchase proposal credits.  Once the paywall is created, the
// user database is updated and the user is added to the paywall pool.
func (p *politeiawww) generateProposalPaywall(u *user.User) (*user.ProposalPaywall, error) {
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
func (p *politeiawww) verifyProposalPayment(u *user.User) (*util.TxDetails, error) {
	paywall := p.mostRecentProposalPaywall(u)

	// If a TxID exists, the payment has already been verified.
	if paywall.TxID != "" {
		return nil, nil
	}

	// Fetch txs sent to paywall address
	txs, err := util.FetchTxsForAddress(paywall.Address, p.dcrdataHostHTTP())
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

// ProposalCreditsBalance returns the number of proposal credits that the user
// has available to spend.
func ProposalCreditBalance(u *user.User) uint64 {
	return uint64(len(u.UnspentProposalCredits))
}

// UserHasProposalCredits checks to see if the user has any unspent proposal
// credits.
func (p *politeiawww) UserHasProposalCredits(u *user.User) bool {
	// Return true when running unit tests or if paywall is disabled
	if !p.paywallIsEnabled() {
		return true
	}
	return ProposalCreditBalance(u) > 0
}

// SpendProposalCredit updates an unspent proposal credit with the passed in
// censorship token, moves the credit into the user's spent proposal credits
// list, and then updates the user database.
func (p *politeiawww) SpendProposalCredit(u *user.User, token string) error {
	// Skip when running unit tests or if paywall is disabled.
	if !p.paywallIsEnabled() {
		return nil
	}

	if ProposalCreditBalance(u) == 0 {
		return www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	creditToSpend := u.UnspentProposalCredits[0]
	creditToSpend.CensorshipToken = token
	u.SpentProposalCredits = append(u.SpentProposalCredits, creditToSpend)
	u.UnspentProposalCredits = u.UnspentProposalCredits[1:]

	err := p.db.UserUpdate(*u)
	return err
}
