// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"sort"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/google/uuid"
)

func convertWWWUserFromDatabaseUser(user *database.User) www.User {
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

func convertWWWIdentitiesFromDatabaseIdentities(identities []database.Identity) []www.UserIdentity {
	userIdentities := make([]www.UserIdentity, 0, len(identities))
	for _, v := range identities {
		userIdentities = append(userIdentities, convertWWWIdentityFromDatabaseIdentity(v))
	}
	return userIdentities
}

func convertWWWIdentityFromDatabaseIdentity(identity database.Identity) www.UserIdentity {
	return www.UserIdentity{
		Pubkey: hex.EncodeToString(identity.Key[:]),
		Active: database.IsIdentityActive(identity),
	}
}

func (b *backend) getUserByIDStr(userIDStr string) (*database.User, error) {
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUUID,
		}
	}

	user, err := b.db.UserGetById(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotFound,
		}
	}

	return user, nil
}

func filterUserPublicFields(user www.User) www.User {
	return www.User{
		ID:         user.ID,
		Admin:      user.Admin,
		Username:   user.Username,
		Identities: user.Identities,
	}
}

// ProcessUserDetails return the requested user's details. Some fields can be
// omitted or blank depending on the requester's access level.
func (b *backend) ProcessUserDetails(ud *www.UserDetails, isCurrentUser bool, isAdmin bool) (*www.UserDetailsReply, error) {
	// Fetch the database user.
	user, err := b.getUserByIDStr(ud.UserID)
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
func (b *backend) ProcessEditUser(eu *www.EditUser, user *database.User) (*www.EditUserReply, error) {
	if eu.EmailNotifications != nil {
		user.EmailNotifications = *eu.EmailNotifications
	}

	// Update the user in the database.
	err := b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &www.EditUserReply{}, nil
}

// ProcessUserCommentsLikes returns all of the user's comment likes for the
// passed in proposal.
func (b *backend) ProcessUserCommentsLikes(user *database.User, token string) (*www.UserCommentsLikesReply, error) {
	log.Tracef("ProcessUserCommentsLikes: %v %v", user.ID, token)

	// Fetch all like comments for the proposal
	dlc, err := b.decredPropCommentLikes(token)
	if err != nil {
		return nil, fmt.Errorf("decredPropLikeComments: %v", err)
	}

	// Sanity check. Like comments should already be sorted in
	// chronological order.
	sort.SliceStable(dlc, func(i, j int) bool {
		return dlc[i].Timestamp < dlc[j].Timestamp
	})

	b.RLock()
	defer b.RUnlock()

	// Filter out like comments that are from the user
	lc := make([]www.LikeComment, 0, len(dlc))
	for _, v := range dlc {
		userID, ok := b.userPubkeys[v.PublicKey]
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
