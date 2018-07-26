package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

func convertWWWUserFromDatabaseUser(user *database.User) v1.User {
	return v1.User{
		ID:       strconv.FormatUint(user.ID, 10),
		Email:    user.Email,
		Username: user.Username,
		Admin:    user.Admin,
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
		FailedLoginAttempts:             user.FailedLoginAttempts,
		Locked:                          checkUserIsLocked(user.FailedLoginAttempts),
		Identities:                      convertWWWIdentitiesFromDatabaseIdentities(user.Identities),
		ProposalCredits:                 ProposalCreditBalance(user),
	}
}

func convertWWWIdentitiesFromDatabaseIdentities(identities []database.Identity) []v1.UserIdentity {
	userIdentities := make([]v1.UserIdentity, 0, len(identities))
	for _, v := range identities {
		userIdentities = append(userIdentities, convertWWWIdentityFromDatabaseIdentity(v))
	}
	return userIdentities
}

func convertWWWIdentityFromDatabaseIdentity(identity database.Identity) v1.UserIdentity {
	return v1.UserIdentity{
		Pubkey: hex.EncodeToString(identity.Key[:]),
		Active: database.IsIdentityActive(identity),
	}
}

func (b *backend) getUserByIDStr(userIDStr string) (*database.User, error) {
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return nil, err
	}

	user, err := b.db.UserGetById(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusUserNotFound,
		}
	}

	return user, nil
}

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
func (b *backend) logAdminProposalAction(adminUser *database.User, token, action string) error {
	return b.logAdminAction(adminUser, fmt.Sprintf("%v,%v", action, token))
}

func (b *backend) ProcessUserDetails(ud *v1.UserDetails) (*v1.UserDetailsReply, error) {
	// Fetch the database user.
	user, err := b.getUserByIDStr(ud.UserID)
	if err != nil {
		return nil, err
	}

	// Convert the database user into a proper response.
	var udr v1.UserDetailsReply
	udr.User = convertWWWUserFromDatabaseUser(user)

	// Fetch the first page of the user's proposals.
	up := v1.UserProposals{
		UserId: ud.UserID,
	}
	upr, err := b.ProcessUserProposals(&up, false, true)
	if err != nil {
		return nil, err
	}

	udr.User.Proposals = upr.Proposals
	return &udr, nil
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
	case v1.UserEditExpireUpdateKeyVerification:
		user.UpdateKeyVerificationExpiry = expiredTime
	case v1.UserEditExpireResetPasswordVerification:
		user.ResetPasswordVerificationExpiry = expiredTime
	case v1.UserEditClearUserPaywall:
		b.removeUsersFromPool([]uint64{user.ID})

		user.NewUserPaywallAddress = ""
		user.NewUserPaywallAmount = 0
		user.NewUserPaywallTx = "cleared_by_admin"
		user.NewUserPaywallTxNotBefore = 0
		user.NewUserPaywallPollExpiry = 0
	case v1.UserEditUnlock:
		user.FailedLoginAttempts = 0
	default:
		return nil, fmt.Errorf("unsupported user edit action: %v",
			v1.UserEditAction[eu.Action])
	}

	// Update the user in the database.
	err = b.db.UserUpdate(*user)
	return &v1.EditUserReply{}, err
}
