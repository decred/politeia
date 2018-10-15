package main

import (
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
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
func (b *backend) paywallIsEnabled() bool {
	return b.cfg.PaywallAmount != 0 && b.cfg.PaywallXpub != ""
}

// addUserToPaywallPool adds a database user to the paywall pool.
//
// This function must be called WITH the mutex held.
func (b *backend) addUserToPaywallPool(user *database.User, paywallType string) {
	b.userPaywallPool[user.ID] = paywallPoolMember{
		paywallType: paywallType,
		address:     user.NewUserPaywallAddress,
		amount:      user.NewUserPaywallAmount,
		txNotBefore: user.NewUserPaywallTxNotBefore,
		pollExpiry:  user.NewUserPaywallPollExpiry,
	}
}

// addUserToPaywallPoolLock adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) addUserToPaywallPoolLock(user *database.User, paywallType string) {
	if !b.paywallIsEnabled() {
		return
	}

	b.Lock()
	defer b.Unlock()

	b.addUserToPaywallPool(user, paywallType)
}

func (b *backend) updateUserAsPaid(user *database.User, tx string) error {
	user.NewUserPaywallTx = tx
	user.NewUserPaywallPollExpiry = 0
	return b.db.UserUpdate(*user)
}

func (b *backend) derivePaywallInfo(user *database.User) (string, uint64, int64, error) {
	address, err := util.DerivePaywallAddress(b.params,
		b.cfg.PaywallXpub, uint32(user.PaywallAddressIndex))
	if err != nil {
		err = fmt.Errorf("Unable to derive paywall address #%v "+
			"for %v: %v", user.ID.ID(), user.Email, err)
	}

	return address, b.cfg.PaywallAmount, time.Now().Unix(), err
}

func (b *backend) createUserPaywallPoolCopy() map[uuid.UUID]paywallPoolMember {
	b.RLock()
	defer b.RUnlock()

	poolCopy := make(map[uuid.UUID]paywallPoolMember, len(b.userPaywallPool))

	for k, v := range b.userPaywallPool {
		poolCopy[k] = v
	}

	return poolCopy
}

func (b *backend) checkForUserPayments(pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

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

		if poolMember.paywallType != paywallTypeUser {
			continue
		}

		log.Tracef("Checking the user paywall address for user %v...", user.Email)

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

		tx, _, err := util.FetchTxWithBlockExplorers(poolMember.address, poolMember.amount,
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

// checkForProposalPayments checks if any of the proposal paywalls in the
// paywall pool have received a payment.  If so, proposal credits are created
// for the user, the user database is updated, and the user is removed from
// the paywall pool.
func (b *backend) checkForProposalPayments(pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

	// In theory poolMember could be raced during this call. In practice
	// a race will not occur as long as the paywall does not remove
	// poolMembers from the pool while in the middle of polling poolMember
	// addresses.
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

		if poolMember.paywallType != paywallTypeProposal {
			continue
		}

		log.Tracef("Checking proposal paywall address for user %v...", user.Email)

		paywall := b.mostRecentProposalPaywall(user)
		if paywallHasExpired(paywall.PollExpiry) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, poll has expired")
			continue
		}

		tx, err := b.verifyProposalPayment(user)
		if err != nil {
			if err == database.ErrShutdown {
				// The database is shutdown, so stop the thread.
				return false, nil
			}

			log.Errorf("cannot update user with id %v: %v", user.ID, err)
			continue
		}

		// Removed paywall from the in-memory pool if it has
		// been marked as paid.
		if !b.userHasValidProposalPaywall(user) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user just paid")
		} else if tx != nil {
			// Update pool member if payment tx was found but
			// does not have enough confimrations.
			poolMember.txID = tx.ID
			poolMember.txAmount = tx.Amount
			poolMember.txConfirmations = tx.Confirmations

			b.Lock()
			b.userPaywallPool[userID] = poolMember
			b.Unlock()
		}

		time.Sleep(paywallCheckGap)
	}

	return true, userIDsToRemove
}

func (b *backend) removeUsersFromPool(userIDsToRemove []uuid.UUID) {
	b.Lock()
	defer b.Unlock()

	for _, userID := range userIDsToRemove {
		delete(b.userPaywallPool, userID)
	}
}

func (b *backend) checkForPayments() {
	for {
		// Removing pool members from the pool while in the middle of
		// polling can cause a race to occur in checkForProposalPayments.

		userPaywallsToCheck := b.createUserPaywallPoolCopy()

		// Check new user payments.
		shouldContinue, userIDsToRemove := b.checkForUserPayments(userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		b.removeUsersFromPool(userIDsToRemove)

		// Check proposal payments.
		shouldContinue, userIDsToRemove = b.checkForProposalPayments(userPaywallsToCheck)
		if !shouldContinue {
			return
		}
		b.removeUsersFromPool(userIDsToRemove)

		time.Sleep(paywallCheckGap)
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

	b.addUserToPaywallPoolLock(user, paywallTypeUser)
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

	tx, _, err := util.FetchTxWithBlockExplorers(user.NewUserPaywallAddress,
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
		// TODO: Add the user to the in-memory pool.
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
		// Proposal paywalls
		if b.userHasValidProposalPaywall(user) {
			b.addUserToPaywallPool(user, paywallTypeProposal)
			return
		}

		// User paywalls
		if b.HasUserPaid(user) {
			return
		}
		if user.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(user.NewUserPaywallPollExpiry) {
			return
		}

		b.addUserToPaywallPool(user, paywallTypeUser)
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

// mostRecentProposalPaywall returns the most recent paywall that has been
// issued to the user.  Just because a paywall is the most recent paywall does
// not guarantee that it is still valid.  Depending on the circumstances, the
// paywall could have already been paid, could have already expired, or could
// still be valid.
func (b *backend) mostRecentProposalPaywall(user *database.User) *database.ProposalPaywall {
	if len(user.ProposalPaywalls) > 0 {
		return &user.ProposalPaywalls[len(user.ProposalPaywalls)-1]
	}
	return nil
}

// userHasValidProposalPaywall checks if the user has been issued a paywall
// that has not been paid yet and that has not expired yet.  Only one paywall
// per user can be valid at a time, so if a valid paywall exists for the user,
// it will be the most recent paywall.
func (b *backend) userHasValidProposalPaywall(user *database.User) bool {
	p := b.mostRecentProposalPaywall(user)
	return p != nil && p.TxID == "" && !paywallHasExpired(p.PollExpiry)
}

// generateProposalPaywall creates a new proposal paywall for the user that
// enables them to purchase proposal credits.  Once the paywall is created, the
// user database is updated and the user is added to the paywall pool.
func (b *backend) generateProposalPaywall(user *database.User) (*database.ProposalPaywall, error) {
	address, amount, txNotBefore, err := b.derivePaywallInfo(user)
	if err != nil {
		return nil, err
	}
	p := database.ProposalPaywall{
		ID:          uint64(len(user.ProposalPaywalls) + 1),
		CreditPrice: amount,
		Address:     address,
		TxNotBefore: txNotBefore,
		PollExpiry:  time.Now().Add(paywallExpiryDuration).Unix(),
	}
	user.ProposalPaywalls = append(user.ProposalPaywalls, p)

	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	b.addUserToPaywallPool(user, paywallTypeProposal)
	return &p, nil
}

// ProcessProposalPaywallDetails returns a proposal paywall that enables the
// the user to purchase proposal credits. The user can only have one paywall
// active at a time.  If no paywall currently exists, a new one is created and
// the user is added to the paywall pool.
func (b *backend) ProcessProposalPaywallDetails(user *database.User) (*v1.ProposalPaywallDetailsReply, error) {
	log.Tracef("ProcessProposalPaywallDetails")

	// Proposal paywalls cannot be generated until the user has paid their
	// user registration fee.
	if !b.HasUserPaid(user) {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusUserNotPaid,
		}
	}

	var p *database.ProposalPaywall
	if b.userHasValidProposalPaywall(user) {
		// Don't create a new paywall if a valid one already exists.
		p = b.mostRecentProposalPaywall(user)
	} else {
		// Create a new paywall.
		var err error
		p, err = b.generateProposalPaywall(user)
		if err != nil {
			return nil, err
		}
	}

	return &v1.ProposalPaywallDetailsReply{
		CreditPrice:        p.CreditPrice,
		PaywallAddress:     p.Address,
		PaywallTxNotBefore: p.TxNotBefore,
	}, nil
}

// ProcessProposalPaywallPayment checks if the user has a pending paywall
// payment and returns the payment details if one is found.
func (b *backend) ProcessProposalPaywallPayment(user *database.User) (*v1.ProposalPaywallPaymentReply, error) {
	log.Tracef("ProcessProposalPaywallPayment")

	var (
		txID          string
		txAmount      uint64
		confirmations uint64
	)

	b.RLock()
	defer b.RUnlock()

	poolMember, ok := b.userPaywallPool[user.ID]
	if ok {
		txID = poolMember.txID
		txAmount = poolMember.txAmount
		confirmations = poolMember.txConfirmations
	}

	return &v1.ProposalPaywallPaymentReply{
		TxID:          txID,
		TxAmount:      txAmount,
		Confirmations: confirmations,
	}, nil
}

// verifyPropoposalPayment checks whether a payment has been sent to the
// user's proposal paywall address. Proposal credits are created and added to
// the user's account if the payment meets the minimum requirements.
func (b *backend) verifyProposalPayment(user *database.User) (*util.TxDetails, error) {
	paywall := b.mostRecentProposalPaywall(user)

	// If a TxID exists, the payment has already been verified.
	if paywall.TxID != "" {
		return nil, nil
	}

	// Fetch txs sent to paywall address
	txs, err := util.FetchTxsForAddress(paywall.Address)
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
		case tx.Confirmations < b.cfg.MinConfirmationsRequired:
			// Payment tx found but not enough confirmations. Return
			// the tx so that the paywall member can be updated.
			return &tx, nil
		default:
			// Payment tx found that meets all criteria. Create
			// proposal credits and update user db record.
			paywall.TxID = tx.ID
			paywall.TxAmount = tx.Amount
			paywall.NumCredits = tx.Amount / paywall.CreditPrice

			// Create proposal credits
			c := make([]database.ProposalCredit, paywall.NumCredits)
			timestamp := time.Now().Unix()
			for i := uint64(0); i < paywall.NumCredits; i++ {
				c[i] = database.ProposalCredit{
					PaywallID:     paywall.ID,
					Price:         paywall.CreditPrice,
					DatePurchased: timestamp,
					TxID:          paywall.TxID,
				}
			}
			user.UnspentProposalCredits = append(user.UnspentProposalCredits, c...)

			// Update user database.
			err = b.db.UserUpdate(*user)
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
func ProposalCreditBalance(u *database.User) uint64 {
	return uint64(len(u.UnspentProposalCredits))
}

// UserHasProposalCredits checks to see if the user has any unspent proposal
// credits.
func (b *backend) UserHasProposalCredits(u *database.User) bool {
	// Return true when running unit tests or if paywall is disabled
	if b.test || !b.paywallIsEnabled() {
		return true
	}
	return ProposalCreditBalance(u) > 0
}

// SpendProposalCredit updates an unspent proposal credit with the passed in
// censorship token, moves the credit into the user's spent proposal credits
// list, and then updates the user database.
func (b *backend) SpendProposalCredit(u *database.User, token string) error {
	// Skip when running unit tests or if paywall is disabled.
	if b.test || !b.paywallIsEnabled() {
		return nil
	}

	if ProposalCreditBalance(u) == 0 {
		return v1.UserError{
			ErrorCode: v1.ErrorStatusNoProposalCredits,
		}
	}

	creditToSpend := u.UnspentProposalCredits[0]
	creditToSpend.CensorshipToken = token
	u.SpentProposalCredits = append(u.SpentProposalCredits, creditToSpend)
	u.UnspentProposalCredits = u.UnspentProposalCredits[1:]

	err := b.db.UserUpdate(*u)
	return err
}
