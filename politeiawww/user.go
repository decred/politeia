package main

import (
	"encoding/hex"

	"github.com/decred/politeia/politeiawww/api/v1"
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
		Username:   user.Username,
		Identities: user.Identities,
		Proposals:  user.Proposals,
	}
}

// ProcessUserDetails return the requested user's details
// Some fields can be ommitted or blank depending on the
// requester's access level
func (b *backend) ProcessUserDetails(ud *v1.UserDetails, isCurrentUser bool, isAdmin bool) (*v1.UserDetailsReply, error) {

	// Fetch the database user.
	user, err := b.getUserByIDStr(ud.UserID)
	if err != nil {
		return nil, err
	}

	// Convert the database user into a proper response.
	var udr v1.UserDetailsReply
	wwwUser := convertWWWUserFromDatabaseUser(user)

	// Fetch the first page of the user's proposals.
	up := v1.UserProposals{
		UserId: ud.UserID,
	}
	upr, err := b.ProcessUserProposals(&up, isCurrentUser, isAdmin)
	if err != nil {
		return nil, err
	}
	wwwUser.Proposals = upr.Proposals

	// Filter returned fields in case the user isn't the admin or the current user
	if !isAdmin && !isCurrentUser {
		udr.User = filterUserPublicFields(wwwUser)
	} else {
		udr.User = wwwUser
	}

	udr.User.NumOfProposals = b.getCountOfProposalsByUserID(up.UserId)

	return &udr, nil
}
