// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"context"
	"fmt"
	"sort"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/legacy/user"
)

// processUserRegistrationPayment verifies that the provided transaction
// meets the minimum requirements to mark the user as paid, and then does
// that in the user database.
func (p *LegacyPoliteiawww) processUserRegistrationPayment(ctx context.Context, u *user.User) (*www.UserRegistrationPaymentReply, error) {
	var reply www.UserRegistrationPaymentReply
	if p.userHasPaid(*u) {
		reply.HasPaid = true
		return &reply, nil
	}

	if paywallHasExpired(u.NewUserPaywallPollExpiry) {
		err := p.generateNewUserPaywall(u)
		if err != nil {
			return nil, err
		}
		reply.PaywallAddress = u.NewUserPaywallAddress
		reply.PaywallAmount = u.NewUserPaywallAmount
		reply.PaywallTxNotBefore = u.NewUserPaywallTxNotBefore
		return &reply, nil
	}

	tx, _, err := fetchTxWithBlockExplorers(ctx, p.params,
		u.NewUserPaywallAddress, u.NewUserPaywallAmount,
		u.NewUserPaywallTxNotBefore, p.cfg.MinConfirmationsRequired,
		p.dcrdataHostHTTP())
	if err != nil {
		return nil, err
	}

	if tx != "" {
		reply.HasPaid = true

		err = p.updateUserAsPaid(u, tx)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO: Add the user to the in-memory pool.
	}

	return &reply, nil
}

// processUserProposalPaywall returns a proposal paywall that enables the
// the user to purchase proposal credits. The user can only have one paywall
// active at a time.  If no paywall currently exists, a new one is created and
// the user is added to the paywall pool.
func (p *LegacyPoliteiawww) processUserProposalPaywall(u *user.User) (*www.UserProposalPaywallReply, error) {
	log.Tracef("processUserProposalPaywall")

	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &www.UserProposalPaywallReply{}, nil
	}

	// Proposal paywalls cannot be generated until the user has paid their
	// user registration fee.
	if !p.userHasPaid(*u) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	var pp *user.ProposalPaywall
	if p.userHasValidProposalPaywall(u) {
		// Don't create a new paywall if a valid one already exists.
		pp = p.mostRecentProposalPaywall(u)
	} else {
		// Create a new paywall.
		var err error
		pp, err = p.generateProposalPaywall(u)
		if err != nil {
			return nil, err
		}
	}

	return &www.UserProposalPaywallReply{
		CreditPrice:        pp.CreditPrice,
		PaywallAddress:     pp.Address,
		PaywallTxNotBefore: pp.TxNotBefore,
	}, nil
}

// processUserProposalPaywallTx checks if the user has a pending paywall
// payment and returns the payment details if one is found.
func (p *LegacyPoliteiawww) processUserProposalPaywallTx(u *user.User) (*www.UserProposalPaywallTxReply, error) {
	log.Tracef("processUserProposalPaywallTx")

	var (
		txID          string
		txAmount      uint64
		confirmations uint64
	)

	p.RLock()
	defer p.RUnlock()

	poolMember, ok := p.userPaywallPool[u.ID]
	if ok {
		txID = poolMember.txID
		txAmount = poolMember.txAmount
		confirmations = poolMember.txConfirmations
	}

	return &www.UserProposalPaywallTxReply{
		TxID:          txID,
		TxAmount:      txAmount,
		Confirmations: confirmations,
	}, nil
}

// processUserProposalCredits returns a list of the user's unspent proposal
// credits and a list of the user's spent proposal credits.
func (p *LegacyPoliteiawww) processUserProposalCredits(u *user.User) (*www.UserProposalCreditsReply, error) {
	// Convert from database proposal credits to www proposal credits.
	upc := make([]www.ProposalCredit, len(u.UnspentProposalCredits))
	for i, credit := range u.UnspentProposalCredits {
		upc[i] = convertProposalCreditFromUserDB(credit)
	}
	spc := make([]www.ProposalCredit, len(u.SpentProposalCredits))
	for i, credit := range u.SpentProposalCredits {
		spc[i] = convertProposalCreditFromUserDB(credit)
	}

	return &www.UserProposalCreditsReply{
		UnspentCredits: upc,
		SpentCredits:   spc,
	}, nil
}

// processUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (p *LegacyPoliteiawww) processUserPaymentsRescan(ctx context.Context, upr www.UserPaymentsRescan) (*www.UserPaymentsRescanReply, error) {
	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &www.UserPaymentsRescanReply{}, nil
	}

	// Lookup user
	u, err := p.userByIDStr(upr.UserID)
	if err != nil {
		return nil, err
	}

	// Fetch user payments
	payments, err := fetchTxsForAddressNotBefore(ctx, p.params,
		u.NewUserPaywallAddress, u.NewUserPaywallTxNotBefore,
		p.dcrdataHostHTTP())
	if err != nil {
		return nil, fmt.Errorf("FetchTxsForAddressNotBefore: %v", err)
	}

	// Paywalls are in chronological order so sort txs into chronological
	// order to make them easier to work with
	sort.SliceStable(payments, func(i, j int) bool {
		return payments[i].Timestamp < payments[j].Timestamp
	})

	// Sanity check. Paywalls should already be in chronological order.
	paywalls := u.ProposalPaywalls
	sort.SliceStable(paywalls, func(i, j int) bool {
		return paywalls[i].TxNotBefore < paywalls[j].TxNotBefore
	})

	// Check for payments that were missed by paywall polling
	newCredits := make([]user.ProposalCredit, 0, len(payments))
	for _, payment := range payments {
		// Check if the payment transaction corresponds to a user
		// registration payment. A user registration payment may not
		// exist if the registration paywall was cleared by an admin.
		if payment.TxID == u.NewUserPaywallTx {
			continue
		}

		// Check for credits that correspond to the payment.  If a
		// credit is found it means that this payment was not missed by
		// paywall polling and we can continue onto the next payment.
		var found bool
		for _, credit := range u.SpentProposalCredits {
			if credit.TxID == payment.TxID {
				found = true
				break
			}
		}
		if found {
			continue
		}

		for _, credit := range u.UnspentProposalCredits {
			if credit.TxID == payment.TxID {
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Credits were not found for this payment which means that it
		// was missed by paywall polling. Create new credits using the
		// paywall details that correspond to the payment timestamp. If
		// a paywall had not yet been issued, use the current proposal
		// credit price.
		var pp user.ProposalPaywall
		for _, paywall := range paywalls {
			if payment.Timestamp < paywall.TxNotBefore {
				continue
			}
			if payment.Timestamp > paywall.TxNotBefore {
				// Corresponding paywall found
				pp = paywall
				break
			}
		}

		if pp == (user.ProposalPaywall{}) {
			// Paywall not found. This means the tx occurred before
			// any paywalls were issued. Use current credit price.
			pp.CreditPrice = p.cfg.PaywallAmount
		}

		// Don't add credits if the paywall is in the paywall pool
		if pp.TxID == "" && !paywallHasExpired(pp.PollExpiry) {
			continue
		}

		// Ensure payment has minimum number of confirmations
		if payment.Confirmations < p.cfg.MinConfirmationsRequired {
			continue
		}

		// Create proposal credits
		numCredits := payment.Amount / pp.CreditPrice
		c := make([]user.ProposalCredit, numCredits)
		for i := uint64(0); i < numCredits; i++ {
			c[i] = user.ProposalCredit{
				PaywallID:     pp.ID,
				Price:         pp.CreditPrice,
				DatePurchased: time.Now().Unix(),
				TxID:          payment.TxID,
			}
		}
		newCredits = append(newCredits, c...)
	}

	// Update user record
	// We relookup the user record here in case the user has spent proposal
	// credits since the start of this request. Failure to relookup the
	// user record here could result in adding proposal credits to the
	// user's account that have already been spent.
	u, err = p.userByEmail(u.Email)
	if err != nil {
		return nil, fmt.Errorf("UserGet %v", err)
	}

	u.UnspentProposalCredits = append(u.UnspentProposalCredits,
		newCredits...)

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, fmt.Errorf("UserUpdate %v", err)
	}

	// Convert database credits to www credits
	newCreditsWWW := make([]www.ProposalCredit, len(newCredits))
	for i, credit := range newCredits {
		newCreditsWWW[i] = convertProposalCreditFromUserDB(credit)
	}

	return &www.UserPaymentsRescanReply{
		NewCredits: newCreditsWWW,
	}, nil
}

func convertProposalCreditFromUserDB(credit user.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}
