package main

import (
	"encoding/hex"

	"github.com/decred/politeia/politeiawww/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/google/uuid"
)

func convertWWWUserFromDatabaseUser(user *database.User) v1.User {
	return v1.User{
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
		ProposalEmailNotifications:      user.ProposalEmailNotifications,
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
	userID, err := uuid.Parse(userIDStr)
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

func filterUserPublicFields(user v1.User) v1.User {
	return v1.User{
		ID:         user.ID,
		Admin:      user.Admin,
		Username:   user.Username,
		Identities: user.Identities,
	}
}

// ProcessUserDetails return the requested user's details. Some fields can be
// omitted or blank depending on the requester's access level.
func (b *backend) ProcessUserDetails(ud *v1.UserDetails, isCurrentUser bool, isAdmin bool) (*v1.UserDetailsReply, error) {
	// Fetch the database user.
	user, err := b.getUserByIDStr(ud.UserID)
	if err != nil {
		return nil, err
	}

	// Convert the database user into a proper response.
	var udr v1.UserDetailsReply
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
func (b *backend) ProcessEditUser(eu *v1.EditUser, user *database.User) (*v1.EditUserReply, error) {
	if eu.ProposalEmailNotifications != nil {
		user.ProposalEmailNotifications = *eu.ProposalEmailNotifications
	}

	// Update the user in the database.
	err := b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &v1.EditUserReply{}, nil
}

// ProcessProposalAccessTime returns an array of the access times for
// all proposals for an user
func (b *backend) ProcessProposalAccessTime(user *database.User, at v1.GetUserAccessTime) (*www.GetUserAccessTimeReply, error) {
	log.Tracef("ProcessProposalAccessTime")
	return &www.GetUserAccessTimeReply{
		AccessTime: user.ProposalAccessTimes[at.Token],
	}, nil
}

// ProcessSetUserAccessTime inserts new access for some proposal by a given user
func (b *backend) ProcessSetUserAccessTime(user *database.User, uat v1.SetUserAccessTime) (*www.SetUserAccessTimeReply, error) {
	log.Tracef("ProcessSetUserAccessTime")
	pats := user.ProposalAccessTimes
	if pats == nil {
		pats = make(map[string]int64)
	}
	pats[uat.Token] = uat.AccessTime
	user.ProposalAccessTimes = pats
	err := b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}
	return &www.SetUserAccessTimeReply{}, nil
}
