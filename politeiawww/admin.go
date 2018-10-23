package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// logAdminAction logs a string to the admin log file.
//
// This function must be called WITH the mutex held.
func (b *backend) logAdminAction(adminUser *database.User, content string) error {
	if b.test {
		return nil
	}

	f, err := os.OpenFile(b.cfg.AdminLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	dateTimeStr := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = fmt.Fprintf(f, "%v,%v,%v,%v\n", dateTimeStr,
		adminUser.ID, adminUser.Username, content)
	return err
}

// logAdminUserAction logs an admin action on a specific user.
//
// This function must be called WITH the mutex held.
func (b *backend) logAdminUserAction(adminUser, user *database.User, action v1.UserEditActionT, reasonForAction string) error {
	return b.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v,%v",
		v1.UserEditAction[action], user.ID, user.Username, reasonForAction))
}

// logAdminUserAction logs an admin action on a specific user.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) logAdminUserActionLock(adminUser, user *database.User, action v1.UserEditActionT, reasonForAction string) error {
	b.Lock()
	defer b.Unlock()

	return b.logAdminUserAction(adminUser, user, action, reasonForAction)
}

// logAdminProposalAction logs an admin action on a proposal.
//
// This function must be called WITH the mutex held.
func (b *backend) logAdminProposalAction(adminUser *database.User, token, action, reason string) error {
	return b.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v", action, token, reason))
}

func (b *backend) ProcessEditUser(eu *v1.EditUser, adminUser *database.User) (*v1.EditUserReply, error) {
	// Fetch the database user.
	user, err := b.getUserByIDStr(eu.UserID)
	if err != nil {
		return nil, err
	}

	// Validate that the action is valid.
	if eu.Action == v1.UserEditInvalid {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidUserEditAction,
		}
	}

	// Validate that the reason is supplied.
	eu.Reason = strings.TrimSpace(eu.Reason)
	if len(eu.Reason) == 0 {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		}
	}

	// Append this action to the admin log file.
	err = b.logAdminUserActionLock(adminUser, user, eu.Action, eu.Reason)
	if err != nil {
		return nil, err
	}

	// -168 hours is 7 days in the past
	expiredTime := time.Now().Add(-168 * time.Hour).Unix()

	switch eu.Action {
	case v1.UserEditExpireNewUserVerification:
		user.NewUserVerificationExpiry = expiredTime
		user.ResendNewUserVerificationExpiry = expiredTime
	case v1.UserEditExpireUpdateKeyVerification:
		user.UpdateKeyVerificationExpiry = expiredTime
	case v1.UserEditExpireResetPasswordVerification:
		user.ResetPasswordVerificationExpiry = expiredTime
	case v1.UserEditClearUserPaywall:
		b.removeUsersFromPool([]uuid.UUID{user.ID})

		user.NewUserPaywallAmount = 0
		user.NewUserPaywallTx = "cleared_by_admin"
		user.NewUserPaywallPollExpiry = 0
	case v1.UserEditUnlock:
		user.FailedLoginAttempts = 0
	case v1.UserEditDeactivate:
		user.Deactivated = true
	case v1.UserEditReactivate:
		user.Deactivated = false
	default:
		return nil, fmt.Errorf("unsupported user edit action: %v",
			v1.UserEditAction[eu.Action])
	}

	// Update the user in the database.
	err = b.db.UserUpdate(*user)
	return &v1.EditUserReply{}, err
}

// ProcessUsers returns a list of users given a set of filters.
func (b *backend) ProcessUsers(users *v1.Users) (*v1.UsersReply, error) {
	var reply v1.UsersReply
	reply.Users = make([]v1.AbridgedUser, 0)

	emailQuery := strings.ToLower(users.Email)
	usernameQuery := formatUsername(users.Username)

	err := b.db.AllUsers(func(user *database.User) {
		reply.TotalUsers++
		userMatches := true

		// If both emailQuery and usernameQuery are non-empty, the user must
		// match both to be included in the results.
		if emailQuery != "" {
			if !strings.Contains(strings.ToLower(user.Email), emailQuery) {
				userMatches = false
			}
		}

		if usernameQuery != "" && userMatches {
			if !strings.Contains(strings.ToLower(user.Username), usernameQuery) {
				userMatches = false
			}
		}

		if userMatches {
			reply.TotalMatches++
			if reply.TotalMatches < v1.UserListPageSize {
				reply.Users = append(reply.Users, v1.AbridgedUser{
					ID:       user.ID.String(),
					Email:    user.Email,
					Username: user.Username,
				})
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Sort results alphabetically.
	sort.Slice(reply.Users, func(i, j int) bool {
		return reply.Users[i].Username < reply.Users[j].Username
	})

	return &reply, nil
}

// ProcessUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (b *backend) ProcessUserPaymentsRescan(upr v1.UserPaymentsRescan) (*v1.UserPaymentsRescanReply, error) {
	// Lookup user
	userID, err := uuid.Parse(upr.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %v", err)
	}
	user, err := b.db.UserGetById(userID)
	if err != nil {
		return nil, fmt.Errorf("UserGetByID: %v", err)
	}

	// Fetch user payments
	payments, err := util.FetchTxsForAddressNotBefore(user.NewUserPaywallAddress,
		user.NewUserPaywallTxNotBefore)
	if err != nil {
		return nil, fmt.Errorf("FetchTxsForAddressNotBefore: %v", err)
	}

	// Paywalls are in chronological order so sort txs into
	// chronological order to make them easier to work with
	sort.SliceStable(payments, func(i, j int) bool {
		return payments[i].Timestamp < payments[j].Timestamp
	})

	// Sanity check. Paywalls should already be in chronological
	// order.
	paywalls := user.ProposalPaywalls
	sort.SliceStable(paywalls, func(i, j int) bool {
		return paywalls[i].TxNotBefore < paywalls[j].TxNotBefore
	})

	// Check for payments that were missed by paywall polling
	newCredits := make([]database.ProposalCredit, 0, len(payments))
	for _, payment := range payments {
		// Check if the payment transaction corresponds to
		// a user registration payment. A user registration
		// payment may not exist if the registration paywall
		// was cleared by an admin.
		if payment.TxID == user.NewUserPaywallTx {
			continue
		}

		// Check for credits that correspond to the payment.
		// If a credit is found it means that this payment
		// was not missed by paywall polling and we can
		// continue onto the next payment.
		var found bool
		for _, credit := range user.SpentProposalCredits {
			if credit.TxID == payment.TxID {
				found = true
				break
			}
		}
		if found {
			continue
		}

		for _, credit := range user.UnspentProposalCredits {
			if credit.TxID == payment.TxID {
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Credits were not found for this payment which means
		// that it was missed by paywall polling. Create new
		// credits using the paywall details that correspond
		// to the payment timestamp. If a paywall had not yet
		// been issued, use the current proposal credit price.
		var pp database.ProposalPaywall
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

		if pp == (database.ProposalPaywall{}) {
			// Paywall not found. This means the tx occurred before
			// any paywalls were issued. Use current credit price.
			pp.CreditPrice = b.cfg.PaywallAmount
		}

		// Don't add credits if the paywall is in the paywall pool
		if pp.TxID == "" && !paywallHasExpired(pp.PollExpiry) {
			continue
		}

		// Ensure payment has minimum number of confirmations
		if payment.Confirmations < b.cfg.MinConfirmationsRequired {
			continue
		}

		// Create proposal credits
		numCredits := payment.Amount / pp.CreditPrice
		c := make([]database.ProposalCredit, numCredits)
		for i := uint64(0); i < numCredits; i++ {
			c[i] = database.ProposalCredit{
				PaywallID:     pp.ID,
				Price:         pp.CreditPrice,
				DatePurchased: time.Now().Unix(),
				TxID:          payment.TxID,
			}
		}
		newCredits = append(newCredits, c...)
	}

	// Update user record
	// We relookup the user record here in case the user has spent
	// proposal credits since the start of this request. Failure to
	// relookup the user record here could result in adding proposal
	// credits to the user's account that have already been spent.
	user, err = b.db.UserGet(user.Email)
	if err != nil {
		return nil, fmt.Errorf("UserGet %v", err)
	}

	user.UnspentProposalCredits = append(user.UnspentProposalCredits,
		newCredits...)

	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, fmt.Errorf("UserUpdate %v", err)
	}

	// Convert database credits to www credits
	newCreditsWWW := make([]v1.ProposalCredit, len(newCredits))
	for i, credit := range newCredits {
		newCreditsWWW[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &v1.UserPaymentsRescanReply{
		NewCredits: newCreditsWWW,
	}, nil
}
