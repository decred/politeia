// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// convertWWWUserFromDatabaseUser converts a user User to a www User.
func convertWWWUserFromDatabaseUser(user *user.User) www.User {
	return www.User{
		ID:                              user.ID.String(),
		Admin:                           user.Admin,
		Email:                           user.Email,
		Username:                        user.Username,
		NewUserPaywallAddress:           user.NewUserPaywallAddress,
		NewUserPaywallAmount:            user.NewUserPaywallAmount,
		NewUserPaywallTx:                user.NewUserPaywallTx,
		NewUserPaywallTxNotBefore:       user.NewUserPaywallTxNotBefore,
		NewUserPaywallPollExpiry:        user.NewUserPaywallPollExpiry,
		NewUserVerificationToken:        user.NewUserVerificationToken,
		NewUserVerificationExpiry:       user.NewUserVerificationExpiry,
		UpdateKeyVerificationToken:      user.UpdateKeyVerificationToken,
		UpdateKeyVerificationExpiry:     user.UpdateKeyVerificationExpiry,
		ResetPasswordVerificationToken:  user.ResetPasswordVerificationToken,
		ResetPasswordVerificationExpiry: user.ResetPasswordVerificationExpiry,
		LastLoginTime:                   user.LastLoginTime,
		FailedLoginAttempts:             user.FailedLoginAttempts,
		Deactivated:                     user.Deactivated,
		Locked:                          checkUserIsLocked(user.FailedLoginAttempts),
		Identities:                      convertWWWIdentitiesFromDatabaseIdentities(user.Identities),
		ProposalCredits:                 ProposalCreditBalance(user),
		EmailNotifications:              user.EmailNotifications,
	}
}

// convertWWWIdentitiesFromDatabaseIdentities converts a user Identity to a www
// Identity.
func convertWWWIdentitiesFromDatabaseIdentities(identities []user.Identity) []www.UserIdentity {
	userIdentities := make([]www.UserIdentity, 0, len(identities))
	for _, v := range identities {
		userIdentities = append(userIdentities,
			convertWWWIdentityFromDatabaseIdentity(v))
	}
	return userIdentities
}

// convertWWWIdentityFromDatabaseIdentity converts a user Identity to a www
// Identity.
func convertWWWIdentityFromDatabaseIdentity(identity user.Identity) www.UserIdentity {
	return www.UserIdentity{
		Pubkey: hex.EncodeToString(identity.Key[:]),
		Active: user.IsIdentityActive(identity),
	}
}

// filterUserPublicFields creates a filtered copy of a www User that only
// contains public information.
func filterUserPublicFields(user www.User) www.User {
	return www.User{
		ID:         user.ID,
		Admin:      user.Admin,
		Username:   user.Username,
		Identities: user.Identities,
	}
}

// formatUsername normalizes a username to lowercase without leading and
// trailing spaces.
func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername verifies that a username adheres to required policy.
func validateUsername(username string) error {
	if username != formatUsername(username) {
		log.Tracef("validateUsername: not normalized: %s %s",
			username, formatUsername(username))
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	if len(username) < www.PolicyMinUsernameLength ||
		len(username) > www.PolicyMaxUsernameLength {
		log.Tracef("validateUsername: not within bounds: %s",
			username)
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	if !validUsername.MatchString(username) {
		log.Tracef("validateUsername: not valid: %s %s",
			username, validUsername.String())
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	return nil
}

// validatePassword verifies that a password adheres to required policy.
func validatePassword(password string) error {
	if len(password) < www.PolicyMinPasswordLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedPassword,
		}
	}

	return nil
}

// validatePassword verifies that a pubkey is valid and not set to all zeros.
func validatePubkey(publicKey string) ([]byte, error) {
	pk, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	var emptyPK [identity.PublicKeySize]byte
	if len(pk) != len(emptyPK) ||
		bytes.Equal(pk, emptyPK[:]) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	return pk, nil
}

// getUserByIDStr converts userIDStr to a uuid and returns the corresponding
// user if it exists.
func (p *politeiawww) getUserByIDStr(userIDStr string) (*user.User, error) {
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUUID,
		}
	}

	usr, err := p.db.UserGetById(userID)
	if err != nil {
		if err == user.ErrUserNotFound {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return nil, err
	}

	return usr, nil
}

// ProcessUserDetails return the requested user's details. Some fields can be
// omitted or blank depending on the requester's access level.
func (p *politeiawww) ProcessUserDetails(ud *www.UserDetails, isCurrentUser bool, isAdmin bool) (*www.UserDetailsReply, error) {
	// Fetch the database user.
	user, err := p.getUserByIDStr(ud.UserID)
	if err != nil {
		return nil, err
	}

	// Convert the database user into a proper response.
	var udr www.UserDetailsReply
	wwwUser := convertWWWUserFromDatabaseUser(user)

	// Filter returned fields in case the user isn't the admin or the current user
	if !isAdmin && !isCurrentUser {
		udr.User = filterUserPublicFields(wwwUser)
	} else {
		udr.User = wwwUser
	}

	return &udr, nil
}

// ProcessEditUser edits a user's preferences.
func (p *politeiawww) ProcessEditUser(eu *www.EditUser, user *user.User) (*www.EditUserReply, error) {
	if eu.EmailNotifications != nil {
		user.EmailNotifications = *eu.EmailNotifications
	}

	// Update the user in the database.
	err := p.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &www.EditUserReply{}, nil
}

// ProcessUserCommentsLikes returns all of the user's comment likes for the
// passed in proposal.
func (p *politeiawww) ProcessUserCommentsLikes(user *user.User, token string) (*www.UserCommentsLikesReply, error) {
	log.Tracef("ProcessUserCommentsLikes: %v %v", user.ID, token)

	// Fetch all like comments for the proposal
	dlc, err := p.decredPropCommentLikes(token)
	if err != nil {
		return nil, fmt.Errorf("decredPropLikeComments: %v", err)
	}

	// Sanity check. Like comments should already be sorted in
	// chronological order.
	sort.SliceStable(dlc, func(i, j int) bool {
		return dlc[i].Timestamp < dlc[j].Timestamp
	})

	p.RLock()
	defer p.RUnlock()

	// Filter out like comments that are from the user
	lc := make([]www.LikeComment, 0, len(dlc))
	for _, v := range dlc {
		userID, ok := p.userPubkeys[v.PublicKey]
		if !ok {
			log.Errorf("getUserCommentLikes: userID lookup failed for "+
				"token:%v commentID:%v pubkey:%v", v.Token, v.CommentID,
				v.PublicKey)
			continue
		}

		if user.ID.String() == userID {
			lc = append(lc, convertLikeCommentFromDecred(v))
		}
	}

	// Compute the resulting like comment action for each comment.
	// The resulting action depends on the order of the like
	// comment actions.
	//
	// Example: when a user upvotes a comment twice, the second
	// upvote cancels out the first upvote and the resulting
	// comment score is 0.
	//
	// Example: when a user upvotes a comment and then downvotes
	// the same comment, the downvote takes precedent and the
	// resulting comment score is -1.
	actions := make(map[string]string) // [commentID]action
	for _, v := range lc {
		prevAction := actions[v.CommentID]
		switch {
		case v.Action == prevAction:
			// New action is the same as the previous action so
			// we undo the previous action.
			actions[v.CommentID] = ""
		case v.Action != prevAction:
			// New action is different than the previous action
			// so the new action takes precedent.
			actions[v.CommentID] = v.Action
		}
	}

	cl := make([]www.CommentLike, 0, len(lc))
	for k, v := range actions {
		// Skip actions that have been taken away
		if v == "" {
			continue
		}
		cl = append(cl, www.CommentLike{
			Token:     token,
			CommentID: k,
			Action:    v,
		})
	}

	return &www.UserCommentsLikesReply{
		CommentsLikes: cl,
	}, nil
}

//
// admin user code follows
//

// _logAdminAction logs a string to the admin log file.
//
// This function must be called WITH the mutex held.
func (p *politeiawww) _logAdminAction(adminUser *user.User, content string) error {
	if p.test {
		return nil
	}

	f, err := os.OpenFile(p.cfg.AdminLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	dateTimeStr := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = fmt.Fprintf(f, "%v,%v,%v,%v\n", dateTimeStr,
		adminUser.ID, adminUser.Username, content)
	return err
}

// logAdminAction logs a string to the admin log file.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) logAdminAction(adminUser *user.User, content string) error {
	p.Lock()
	defer p.Unlock()

	return p._logAdminAction(adminUser, content)
}

// logAdminUserAction logs an admin action on a specific user.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) logAdminUserAction(adminUser, user *user.User, action v1.UserManageActionT, reasonForAction string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v,%v",
		v1.UserManageAction[action], user.ID, user.Username, reasonForAction))
}

// logAdminProposalAction logs an admin action on a proposal.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) logAdminProposalAction(adminUser *user.User, token, action, reason string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v", action, token, reason))
}

func (p *politeiawww) ProcessManageUser(mu *v1.ManageUser, adminUser *user.User) (*v1.ManageUserReply, error) {
	// Fetch the database user.
	user, err := p.getUserByIDStr(mu.UserID)
	if err != nil {
		return nil, err
	}

	// Validate that the action is valid.
	if mu.Action == v1.UserManageInvalid {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidUserManageAction,
		}
	}

	// Validate that the reason is supplied.
	mu.Reason = strings.TrimSpace(mu.Reason)
	if len(mu.Reason) == 0 {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		}
	}

	// -168 hours is 7 days in the past
	expiredTime := time.Now().Add(-168 * time.Hour).Unix()

	switch mu.Action {
	case v1.UserManageExpireNewUserVerification:
		user.NewUserVerificationExpiry = expiredTime
		user.ResendNewUserVerificationExpiry = expiredTime
	case v1.UserManageExpireUpdateKeyVerification:
		user.UpdateKeyVerificationExpiry = expiredTime
	case v1.UserManageExpireResetPasswordVerification:
		user.ResetPasswordVerificationExpiry = expiredTime
	case v1.UserManageClearUserPaywall:
		p.removeUsersFromPool([]uuid.UUID{user.ID})

		user.NewUserPaywallAmount = 0
		user.NewUserPaywallTx = "cleared_by_admin"
		user.NewUserPaywallPollExpiry = 0
	case v1.UserManageUnlock:
		user.FailedLoginAttempts = 0
	case v1.UserManageDeactivate:
		user.Deactivated = true
	case v1.UserManageReactivate:
		user.Deactivated = false
	default:
		return nil, fmt.Errorf("unsupported user edit action: %v",
			v1.UserManageAction[mu.Action])
	}

	// Update the user in the database.
	err = p.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	if !p.test {
		p.fireEvent(EventTypeUserManage, EventDataUserManage{
			AdminUser:  adminUser,
			User:       user,
			ManageUser: mu,
		})
	}

	return &v1.ManageUserReply{}, nil
}

// ProcessUsers returns a list of users given a set of filters.
func (p *politeiawww) ProcessUsers(users *v1.Users) (*v1.UsersReply, error) {
	var reply v1.UsersReply
	reply.Users = make([]v1.AbridgedUser, 0)

	emailQuery := strings.ToLower(users.Email)
	usernameQuery := formatUsername(users.Username)

	err := p.db.AllUsers(func(user *user.User) {
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
func (p *politeiawww) ProcessUserPaymentsRescan(upr v1.UserPaymentsRescan) (*v1.UserPaymentsRescanReply, error) {
	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &v1.UserPaymentsRescanReply{}, nil
	}

	// Lookup user
	u, err := p.getUserByIDStr(upr.UserID)
	if err != nil {
		return nil, err
	}

	// Fetch user payments
	payments, err := util.FetchTxsForAddressNotBefore(u.NewUserPaywallAddress,
		u.NewUserPaywallTxNotBefore)
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
	paywalls := u.ProposalPaywalls
	sort.SliceStable(paywalls, func(i, j int) bool {
		return paywalls[i].TxNotBefore < paywalls[j].TxNotBefore
	})

	// Check for payments that were missed by paywall polling
	newCredits := make([]user.ProposalCredit, 0, len(payments))
	for _, payment := range payments {
		// Check if the payment transaction corresponds to
		// a user registration payment. A user registration
		// payment may not exist if the registration paywall
		// was cleared by an admin.
		if payment.TxID == u.NewUserPaywallTx {
			continue
		}

		// Check for credits that correspond to the payment.
		// If a credit is found it means that this payment
		// was not missed by paywall polling and we can
		// continue onto the next payment.
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

		// Credits were not found for this payment which means
		// that it was missed by paywall polling. Create new
		// credits using the paywall details that correspond
		// to the payment timestamp. If a paywall had not yet
		// been issued, use the current proposal credit price.
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
	// We relookup the user record here in case the user has spent
	// proposal credits since the start of this request. Failure to
	// relookup the user record here could result in adding proposal
	// credits to the user's account that have already been spent.
	u, err = p.db.UserGet(u.Email)
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
	newCreditsWWW := make([]v1.ProposalCredit, len(newCredits))
	for i, credit := range newCredits {
		newCreditsWWW[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &v1.UserPaymentsRescanReply{
		NewCredits: newCreditsWWW,
	}, nil
}
