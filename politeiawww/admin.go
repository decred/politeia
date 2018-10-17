package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
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
	case v1.UserEditExpireUpdateKeyVerification:
		user.UpdateKeyVerificationExpiry = expiredTime
	case v1.UserEditExpireResetPasswordVerification:
		user.ResetPasswordVerificationExpiry = expiredTime
	case v1.UserEditClearUserPaywall:
		b.removeUsersFromPool([]uuid.UUID{user.ID})

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
