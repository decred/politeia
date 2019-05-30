// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/golangcrypto/bcrypt"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

const (
	LoginAttemptsToLockUser = 5

	// Route to reset password at GUI
	ResetPasswordGuiRoute = "/password" // XXX what is this doing here?

	emailRegex = `^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

var (
	validUsername = regexp.MustCompile(createUsernameRegex())
	validEmail    = regexp.MustCompile(emailRegex)

	// MinimumLoginWaitTime is the minimum amount of time to wait before the
	// server sends a response to the client for the login route. This is done
	// to prevent an attacker from executing a timing attack to determine whether
	// the ErrorStatusInvalidEmailOrPassword response is specific to a bad email
	// or bad password.
	MinimumLoginWaitTime = 500 * time.Millisecond
)

type loginReplyWithError struct {
	reply *www.LoginReply
	err   error
}

// createUsernameRegex generates a regex based on the policy supplied valid
// characters in a user name.
func createUsernameRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range www.PolicyUsernameSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(www.PolicyMinUsernameLength) + ",")
	buf.WriteString(strconv.Itoa(www.PolicyMaxUsernameLength) + "}$")

	return buf.String()
}

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
func convertWWWIdentityFromDatabaseIdentity(id user.Identity) www.UserIdentity {
	return www.UserIdentity{
		Pubkey: id.String(),
		Active: id.IsActive(),
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
		log.Debugf("validatePubkey: decode hex string "+
			"failed for '%v': %v", publicKey, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	var emptyPK [identity.PublicKeySize]byte
	switch {
	case len(pk) != len(emptyPK):
		log.Debugf("validatePubkey: invalid size: %v",
			publicKey)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	case bytes.Equal(pk, emptyPK[:]):
		log.Debugf("validatePubkey: pubkey is empty: %v",
			publicKey)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	return pk, nil
}

// checkPublicKeyAndSignature validates the public key and signature.
func checkPublicKeyAndSignature(u *user.User, publicKey string, signature string, elements ...string) error {
	id, err := checkPublicKey(u, publicKey)
	if err != nil {
		return err
	}

	return checkSignature(id, signature, elements...)
}

// checkPublicKey compares the supplied public key against the one stored in
// the user database. It will return the active identity if there are no
// errors.
func checkPublicKey(u *user.User, pk string) ([]byte, error) {
	if u.PublicKey() != pk {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}
	return u.ActiveIdentity().Key[:], nil
}

// initUserPubkeys initializes the userPubkeys map with all the pubkey-userid
// associations that are found in the database.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) initUserPubkeys() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		userId := u.ID.String()
		for _, v := range u.Identities {
			key := hex.EncodeToString(v.Key[:])
			p.userPubkeys[key] = userId
		}
	})
}

// setUserPubkeyAssociaton associates a public key with a user id in
// the userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) setUserPubkeyAssociaton(u *user.User, publicKey string) {
	p.Lock()
	defer p.Unlock()

	p.userPubkeys[publicKey] = u.ID.String()
}

// removeUserPubkeyAssociaton removes a public key from the
// userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) removeUserPubkeyAssociaton(u *user.User, publicKey string) {
	p.Lock()
	defer p.Unlock()

	delete(p.userPubkeys, publicKey)
}

// initUserEmails initializes the userEmails cache by iterating through all the
// users in the database and adding a email-userID mapping for them.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) initUserEmails() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		p.userEmails[u.Email] = u.ID
	})
}

// setUserEmails sets a email-userID mapping in the user emails cache.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) setUserEmails(email string, id uuid.UUID) {
	p.Lock()
	defer p.Unlock()
	p.userEmails[email] = id
}

// userIDByEmail returns a userID given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) userIDByEmail(email string) (uuid.UUID, bool) {
	p.RLock()
	defer p.RUnlock()
	id, ok := p.userEmails[email]
	return id, ok
}

// userByEmail returns a User object given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) userByEmail(email string) (*user.User, error) {
	id, ok := p.userIDByEmail(email)
	if !ok {
		log.Debugf("userByEmail: email lookup failed for '%v'", email)
		return nil, user.ErrUserNotFound
	}
	return p.db.UserGetById(id)
}

// checkSignature validates an incoming signature against the specified user's
// pubkey.
func checkSignature(id []byte, signature string, elements ...string) error {
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(id)
	if err != nil {
		return err
	}
	var msg string
	for _, v := range elements {
		msg += v
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	return nil
}

// generateVerificationTokenAndExpiry creates a new verification token that
// expires in www.VerificationExpiryHours hours.
func generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	duration := time.Duration(www.VerificationExpiryHours) * time.Hour
	expiry := time.Now().Add(duration).Unix()

	return token, expiry, nil
}

// checkUserIsLocked checks if a user is locked after too many login attempts
func checkUserIsLocked(failedLoginAttempts uint64) bool {
	return failedLoginAttempts >= LoginAttemptsToLockUser
}

// setNewUserVerificationAndIdentity adds an identity to a user.
func setNewUserVerificationAndIdentity(u *user.User, token []byte, expiry int64, includeResend bool, pk []byte) {
	u.NewUserVerificationToken = token
	u.NewUserVerificationExpiry = expiry
	if includeResend {
		// This field is used to support requesting another
		// registration email quickly, without having to wait the full
		// email-spam-prevention period.
		u.ResendNewUserVerificationExpiry = expiry
	}
	u.Identities = []user.Identity{{
		Activated: time.Now().Unix(),
	}}
	copy(u.Identities[0].Key[:], pk)
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (p *politeiawww) hashPassword(password string) ([]byte, error) {
	if p.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
}

// getUserIDByPubKey return uuid that corresponds to the provided public key.
func (p *politeiawww) getUserIDByPubKey(pubkey string) (string, bool) {
	p.RLock()
	defer p.RUnlock()

	userID, ok := p.userPubkeys[pubkey]
	return userID, ok
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

// getUsernameById returns the username given its id. If the id is invalid,
// it returns an empty string.
func (p *politeiawww) getUsernameById(userIdStr string) string {
	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return ""
	}

	u, err := p.db.UserGetById(userId)
	if err != nil {
		return ""
	}

	return u.Username
}

// validatePubkeyIsUnique ensures that the provided public key is unique.
// XXX this function does too much. Why are we sending in a pointer to
// XXX user.User?
func (p *politeiawww) validatePubkeyIsUnique(publicKey string, u *user.User) error {
	p.RLock()
	userIDStr, ok := p.userPubkeys[publicKey]
	p.RUnlock()
	if !ok {
		return nil
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return err
	}

	if u != nil && u.ID == userID {
		return nil
	}

	return www.UserError{
		ErrorCode: www.ErrorStatusDuplicatePublicKey,
	}
}

// processUserDetails return the requested user's details. Some fields can be
// omitted or blank depending on the requester's access level.
func (p *politeiawww) processUserDetails(ud *www.UserDetails, isCurrentUser bool, isAdmin bool) (*www.UserDetailsReply, error) {
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

// processEditUser edits a user's preferences.
func (p *politeiawww) processEditUser(eu *www.EditUser, user *user.User) (*www.EditUserReply, error) {
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

// processUserCommentsLikes returns all of the user's comment likes for the
// passed in proposal.
func (p *politeiawww) processUserCommentsLikes(user *user.User, token string) (*www.UserCommentsLikesReply, error) {
	log.Tracef("processUserCommentsLikes: %v %v", user.ID, token)

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

// login attempts to login a a user.
func (p *politeiawww) login(l *www.Login) loginReplyWithError {
	// Get user from db.
	u, err := p.userByEmail(l.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("Login failure for %v: user not found in database",
				l.Email)
			return loginReplyWithError{
				reply: nil,
				err: www.UserError{
					ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
				},
			}
		}

		return loginReplyWithError{
			reply: nil,
			err:   err,
		}
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		if !checkUserIsLocked(u.FailedLoginAttempts) {
			u.FailedLoginAttempts++
			err := p.db.UserUpdate(*u)
			if err != nil {
				return loginReplyWithError{
					reply: nil,
					err:   err,
				}
			}

			// Check if the user is locked again so we can send an
			// email.
			if checkUserIsLocked(u.FailedLoginAttempts) && !p.test {
				// This is conditional on the email server
				// being setup.
				err := p.emailUserLocked(u.Email)
				if err != nil {
					return loginReplyWithError{
						reply: nil,
						err:   err,
					}
				}
			}
		}

		log.Debugf("Login failure for %v: incorrect password",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
			},
		}
	}

	// Check that the user is verified.
	if u.NewUserVerificationToken != nil {
		log.Debugf("Login failure for %v: user not yet verified",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusEmailNotVerified,
			},
		}
	}

	// Check if the user account is deactivated.
	if u.Deactivated {
		log.Debugf("Login failure for %v: user deactivated", l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		}
	}

	// Check if user is locked due to too many login attempts
	if checkUserIsLocked(u.FailedLoginAttempts) {
		log.Debugf("Login failure for %v: user locked",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		}
	}

	lastLoginTime := u.LastLoginTime
	u.FailedLoginAttempts = 0
	u.LastLoginTime = time.Now().Unix()
	err = p.db.UserUpdate(*u)
	if err != nil {
		return loginReplyWithError{
			reply: nil,
			err:   err,
		}
	}
	reply, err := p.createLoginReply(u, lastLoginTime)
	return loginReplyWithError{
		reply: reply,
		err:   err,
	}
}

// emailResetPassword handles the reset password command.
func (p *politeiawww) emailResetPassword(u *user.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	if u.ResetPasswordVerificationToken != nil {
		if u.ResetPasswordVerificationExpiry > time.Now().Unix() {
			// The verification token is present and hasn't
			// expired, so do nothing.
			return nil
		}
	}

	// The verification token isn't present or is present but expired.

	// Generate a new verification token and expiry.
	token, expiry, err := generateVerificationTokenAndExpiry()
	if err != nil {
		return err
	}

	// Add the updated user information to the db.
	u.ResetPasswordVerificationToken = token
	u.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*u)
	if err != nil {
		return err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailResetPasswordVerificationLink(rp.Email,
			hex.EncodeToString(token))
		if err != nil {
			return err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		rpr.VerificationToken = hex.EncodeToString(token)
	}

	return nil
}

// verifyResetPassword verifies the reset password command.
func (p *politeiawww) verifyResetPassword(u *user.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	// Decode the verification token.
	token, err := hex.DecodeString(rp.VerificationToken)
	if err != nil {
		log.Debugf("VerifyResetPassword failure for %v: verification "+
			"token could not be decoded: %v", rp.Email, err)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.ResetPasswordVerificationToken) {
		log.Debugf("VerifyResetPassword failure for %v: verification "+
			"token doesn't match, expected %v", rp.Email,
			u.ResetPasswordVerificationToken)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if u.ResetPasswordVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyResetPassword failure for %v: verification "+
			"token is expired", rp.Email)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Validate the new password.
	err = validatePassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Hash the new password.
	hashedPassword, err := p.hashPassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Clear out the verification token fields, set the new password in the
	// db, and unlock account
	u.ResetPasswordVerificationToken = nil
	u.ResetPasswordVerificationExpiry = 0
	u.HashedPassword = hashedPassword
	u.FailedLoginAttempts = 0

	return p.db.UserUpdate(*u)
}

// createLoginReply creates a login reply.
func (p *politeiawww) createLoginReply(u *user.User, lastLoginTime int64) (*www.LoginReply, error) {
	reply := www.LoginReply{
		IsAdmin:         u.Admin,
		UserID:          u.ID.String(),
		Email:           u.Email,
		Username:        u.Username,
		PublicKey:       u.PublicKey(),
		PaywallTxID:     u.NewUserPaywallTx,
		ProposalCredits: ProposalCreditBalance(u),
		LastLoginTime:   lastLoginTime,
	}

	if !p.HasUserPaid(u) {
		err := p.GenerateNewUserPaywall(u)
		if err != nil {
			return nil, err
		}

		reply.PaywallAddress = u.NewUserPaywallAddress
		reply.PaywallAmount = u.NewUserPaywallAmount
		reply.PaywallTxNotBefore = u.NewUserPaywallTxNotBefore
	}

	return &reply, nil
}

// processNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply.  The caller shall
// verify error and determine how to return this information upstream.
func (p *politeiawww) processNewUser(u www.NewUser) (*www.NewUserReply, error) {
	var (
		reply  www.NewUserReply
		token  []byte
		expiry int64
	)

	existingUser, err := p.userByEmail(u.Email)
	switch err {
	case nil:
		// User exists
		// Check if the user is already verified.
		if existingUser.NewUserVerificationToken == nil {
			log.Debugf("processNewUser: user is already verified")
			return &reply, nil
		}

		// Check if the verification token is expired. If the token is
		// not expired then we simply return. If the token is expired
		// then we treat this request as a standard NewUser request. A
		// new token is emailed to the user and the database is updated.
		// The user is allowed to use a new pubkey if they want to update
		// their identity.
		if existingUser.NewUserVerificationExpiry > time.Now().Unix() {
			log.Debugf("processNewUser: user is unverified and " +
				"verification token has not yet expired")
			return &reply, nil
		}
	case user.ErrUserNotFound:
		// Doesn't exist, create new user.
	default:
		// All other errors
		return nil, err
	}

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Format and validate the username.
	username := formatUsername(u.Username)
	err = validateUsername(username)
	if err != nil {
		return nil, err
	}

	// Validate the password.
	err = validatePassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Validate email.
	if !validEmail.MatchString(u.Email) {
		log.Debugf("processNewUser: invalid email '%v'", u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedEmail,
		}
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(u.PublicKey, existingUser)
	if err != nil {
		return nil, err
	}

	// Ensure username is unique
	if existingUser == nil {
		_, err = p.db.UserGetByUsername(u.Username)
		switch err {
		case nil:
			// Duplicate username
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			}
		case user.ErrUserNotFound:
			// Username doesn't exist; continue
		default:
			return nil, err
		}
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Generate the verification token and expiry.
	token, expiry, err = generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Create a new database user with the provided information.
	newUser := user.User{
		Email:          strings.ToLower(u.Email),
		Username:       username,
		HashedPassword: hashedPassword,
		Admin:          false,
	}
	setNewUserVerificationAndIdentity(&newUser, token, expiry, false, pk)

	if !p.test {
		// Try to email the verification link first; if it fails, then
		// the new user won't be created.
		//
		// This is conditional on the email server being setup.
		err := p.emailNewUserVerificationLink(u.Email, hex.EncodeToString(token), u.Username)
		if err != nil {
			log.Errorf("Email new user verification link failed %v, %v", u.Email, err)
			return &reply, nil
		}
	}

	// Check if the user already exists.
	if existingUser != nil {
		existingPublicKey := hex.EncodeToString(existingUser.Identities[0].Key[:])
		p.removeUserPubkeyAssociaton(existingUser, existingPublicKey)

		// Update the user in the db.
		newUser.ID = existingUser.ID
		err = p.db.UserUpdate(newUser)
		if err != nil {
			return nil, err
		}
	} else {
		// Save the new user in the db.
		err = p.db.UserNew(newUser)
		if err != nil {
			return nil, err
		}

		// Update user emails cache. The user ID needs to be
		// looked up first.
		u, err := p.db.UserGetByUsername(newUser.Username)
		if err != nil {
			return nil, fmt.Errorf("userByUsername '%v': %v",
				newUser.Username, err)
		}

		p.setUserEmails(u.Email, u.ID)
	}

	// Get user that we just inserted so we can use their numerical user
	// ID (N) to derive the Nth paywall address from the paywall extended
	// public key.
	//
	// Even if existingUser is non-nil, this will bring it up-to-date
	// with the new information inserted via newUser.
	existingUser, err = p.userByEmail(newUser.Email)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve account info for %v: %v",
			newUser.Email, err)
	}

	// Associate the user id with the new public key.
	p.setUserPubkeyAssociaton(existingUser, u.PublicKey)

	// Derive paywall information for this user if the paywall is enabled.
	err = p.GenerateNewUserPaywall(existingUser)
	if err != nil {
		return nil, err
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		reply.VerificationToken = hex.EncodeToString(token)
	}

	log.Debugf("New user created: %v", u.Username)

	return &reply, nil
}

// processVerifyNewUser verifies the token generated for a recently created
// user.  It ensures that the token matches with the input and that the token
// hasn't expired.  On success it returns database user record.
func (p *politeiawww) processVerifyNewUser(usr www.VerifyNewUser) (*user.User, error) {
	// Check that the user already exists.
	u, err := p.userByEmail(usr.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("VerifyNewUser failure for %v: user not found",
				usr.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(usr.VerificationToken)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: verification token could "+
			"not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.NewUserVerificationToken) {
		log.Debugf("VerifyNewUser: wrong token for user %v "+
			"got %v, want %v", u.Email, hex.EncodeToString(token),
			hex.EncodeToString(u.NewUserVerificationToken))
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if time.Now().Unix() > u.NewUserVerificationExpiry {
		log.Debugf("VerifyNewUser failure for %v: verification token expired",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(usr.Signature)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: signature could not be "+
			"decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	var pi *identity.PublicIdentity
	for _, v := range u.Identities {
		if v.Deactivated != 0 {
			continue
		}
		pi, err = identity.PublicIdentityFromBytes(v.Key[:])
		if err != nil {
			return nil, err
		}
	}
	if pi == nil {
		log.Debugf("VerifyNewUser failure for %v: no public key",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if !pi.VerifyMessage([]byte(usr.VerificationToken), sig) {
		log.Debugf("VerifyNewUser failure for %v: signature doesn't match "+
			"(pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Clear out the verification token fields in the db.
	u.NewUserVerificationToken = nil
	u.NewUserVerificationExpiry = 0
	u.ResendNewUserVerificationExpiry = 0
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeUser)

	return u, nil
}

// processResendVerification resends a new user verification email if the
// user exists and his verification token is expired.
func (p *politeiawww) processResendVerification(rv *www.ResendVerification) (*www.ResendVerificationReply, error) {
	rvr := www.ResendVerificationReply{}

	// Get user from db.
	u, err := p.userByEmail(rv.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("ResendVerification failure for %v: user not found",
				rv.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return nil, err
	}

	// Don't do anything if the user is already verified or the token hasn't
	// expired yet.
	if u.NewUserVerificationToken == nil {
		log.Debugf("ResendVerification failure for %v: user already verified",
			rv.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusEmailAlreadyVerified,
		}
	}

	if u.ResendNewUserVerificationExpiry > time.Now().Unix() {
		log.Debugf("ResendVerification failure for %v: verification token "+
			"not expired yet", rv.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
		}
	}

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(rv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(rv.PublicKey, u)
	if err != nil {
		return nil, err
	}

	// Generate the verification token and expiry.
	token, expiry, err := generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Remove the original pubkey from the cache.
	existingPublicKey := hex.EncodeToString(u.Identities[0].Key[:])
	p.removeUserPubkeyAssociaton(u, existingPublicKey)

	// Set a new verificaton token and identity.
	setNewUserVerificationAndIdentity(u, token, expiry, true, pk)

	// Associate the user id with the new identity.
	p.setUserPubkeyAssociaton(u, rv.PublicKey)

	// Update the user in the db.
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailNewUserVerificationLink(u.Email,
			hex.EncodeToString(token), u.Username)
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		rvr.VerificationToken = hex.EncodeToString(token)
	}
	return &rvr, nil
}

// processUpdateUserKey sets a verification token and expiry to allow the user to
// update his key pair; the token must be verified before it expires. If the
// token is already set and is expired, it generates a new one.
func (p *politeiawww) processUpdateUserKey(usr *user.User, u www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	var reply www.UpdateUserKeyReply
	var token []byte
	var expiry int64

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(u.PublicKey, nil)
	if err != nil {
		return nil, err
	}

	// Check if the verification token hasn't expired yet.
	if usr.UpdateKeyVerificationToken != nil {
		if usr.UpdateKeyVerificationExpiry > time.Now().Unix() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
				ErrorContext: []string{
					strconv.FormatInt(usr.UpdateKeyVerificationExpiry, 10),
				},
			}
		}
	}

	// Generate a new verification token and expiry.
	token, expiry, err = generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	usr.UpdateKeyVerificationToken = token
	usr.UpdateKeyVerificationExpiry = expiry

	identity := user.Identity{}
	copy(identity.Key[:], pk)
	usr.Identities = append(usr.Identities, identity)

	err = p.db.UserUpdate(*usr)
	if err != nil {
		return nil, err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailUpdateUserKeyVerificationLink(usr.Email, u.PublicKey,
			hex.EncodeToString(token))
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		reply.VerificationToken = hex.EncodeToString(token)
	}
	return &reply, nil
}

// processVerifyUpdateUserKey verifies the token generated for the recently
// generated key pair. It ensures that the token matches with the input and
// that the token hasn't expired.
func (p *politeiawww) processVerifyUpdateUserKey(u *user.User, vu www.VerifyUpdateUserKey) (*user.User, error) {
	// Decode the verification token.
	token, err := hex.DecodeString(vu.VerificationToken)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification "+
			"token could not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.UpdateKeyVerificationToken) {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification "+
			"token doesn't match, expected %v", u.Email,
			u.UpdateKeyVerificationToken, token)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if u.UpdateKeyVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification "+
			"token not expired yet", u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(vu.Signature)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature "+
			"could not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	id := u.Identities[len(u.Identities)-1]
	pi, err := identity.PublicIdentityFromBytes(id.Key[:])
	if err != nil {
		return nil, err
	}

	if !pi.VerifyMessage([]byte(vu.VerificationToken), sig) {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature did"+
			" not match (pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Associate the user id with the new public key.
	p.setUserPubkeyAssociaton(u, pi.String())

	// Clear out the verification token fields in the db and activate
	// the key and deactivate the one it's replacing.
	u.UpdateKeyVerificationToken = nil
	u.UpdateKeyVerificationExpiry = 0

	t := time.Now().Unix()
	for k, v := range u.Identities {
		if v.Deactivated == 0 {
			u.Identities[k].Deactivated = t
			break
		}
	}
	u.Identities[len(u.Identities)-1].Activated = t
	u.Identities[len(u.Identities)-1].Deactivated = 0

	return u, p.db.UserUpdate(*u)
}

// processLogin checks that a user exists, is verified, and has
// the correct password.
func (p *politeiawww) processLogin(l www.Login) (*www.LoginReply, error) {
	var (
		r       loginReplyWithError
		login   = make(chan loginReplyWithError)
		timeout = make(chan bool)
	)

	go func() {
		login <- p.login(&l)
	}()
	go func() {
		time.Sleep(MinimumLoginWaitTime)
		timeout <- true
	}()

	// Execute both goroutines in parallel, and only return
	// when both are finished.
	select {
	case r = <-login:
	case <-timeout:
	}

	select {
	case r = <-login:
	case <-timeout:
	}

	return r.reply, r.err
}

// processChangeUsername checks that the password matches the one
// in the database, then checks that the username is valid and not
// already taken, then changes the user record in the database to
// the new username.
func (p *politeiawww) processChangeUsername(email string, cu www.ChangeUsername) (*www.ChangeUsernameReply, error) {
	var reply www.ChangeUsernameReply

	// Get user from db.
	u, err := p.userByEmail(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(cu.Password))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPassword,
		}
	}

	// Format and validate the new username.
	newUsername := formatUsername(cu.NewUsername)
	err = validateUsername(newUsername)
	if err != nil {
		return nil, err
	}

	// Check for duplicate username
	_, err = p.db.UserGetByUsername(newUsername)
	switch err {
	case nil:
		// Duplicate
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Doesn't exist, update username.
	default:
		// All other errors
		return nil, err
	}

	// Add the updated user information to the db.
	u.Username = newUsername
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// processChangePassword checks that the current password matches the one
// in the database, then changes it to the new password.
func (p *politeiawww) processChangePassword(email string, cp www.ChangePassword) (*www.ChangePasswordReply, error) {
	var reply www.ChangePasswordReply

	// Get user from db.
	u, err := p.userByEmail(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(cp.CurrentPassword))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Validate the new password.
	err = validatePassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	u.HashedPassword = hashedPassword
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	err = p.emailUserPasswordChanged(email)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// processResetPassword is intended to be called twice; in the first call, an
// email is provided and the function checks if the user exists. If the user exists, it
// generates a verification token and stores it in the database. In the second
// call, the email, verification token and a new password are provided. If everything
// matches, then the user's password is updated in the database.
func (p *politeiawww) processResetPassword(rp www.ResetPassword) (*www.ResetPasswordReply, error) {
	var reply www.ResetPasswordReply

	// Get user from db.
	u, err := p.userByEmail(rp.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("processResetPassword: user not found %v",
				rp.Email)
			err = www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}

		return nil, err
	}

	if rp.VerificationToken == "" {
		err = p.emailResetPassword(u, rp, &reply)
	} else {
		err = p.verifyResetPassword(u, rp, &reply)
	}

	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// processUserProposalCredits returns a list of the user's unspent proposal
// credits and a list of the user's spent proposal credits.
func processUserProposalCredits(u *user.User) (*www.UserProposalCreditsReply, error) {
	// Convert from database proposal credits to www proposal credits.
	upc := make([]www.ProposalCredit, len(u.UnspentProposalCredits))
	for i, credit := range u.UnspentProposalCredits {
		upc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}
	spc := make([]www.ProposalCredit, len(u.SpentProposalCredits))
	for i, credit := range u.SpentProposalCredits {
		spc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &www.UserProposalCreditsReply{
		UnspentCredits: upc,
		SpentCredits:   spc,
	}, nil
}

// processUserProposals returns a page of proposals for the given user.
func (p *politeiawww) processUserProposals(up *www.UserProposals, isCurrentUser, isAdminUser bool) (*www.UserProposalsReply, error) {
	// Verify user exists
	_, err := p.getUserByIDStr(up.UserId)
	if err != nil {
		return nil, err
	}

	// Get a page of user proposals
	props, ps, err := p.getUserProps(proposalsFilter{
		After:  up.After,
		Before: up.Before,
		UserID: up.UserId,
		StateMap: map[www.PropStateT]bool{
			www.PropStateUnvetted: isCurrentUser || isAdminUser,
			www.PropStateVetted:   true,
		},
	})
	if err != nil {
		return nil, err
	}

	// Find the number of proposals the user has submitted. This
	// number will be different depending on who is requesting it.
	// Non-public proposals are included in the calculation when
	// an admin or the author is requesting the data.
	numProposals := ps.Public + ps.Abandoned
	if isCurrentUser || isAdminUser {
		numProposals += ps.NotReviewed + ps.UnreviewedChanges + ps.Censored
	}

	return &www.UserProposalsReply{
		Proposals:      props,
		NumOfProposals: numProposals,
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
func (p *politeiawww) logAdminUserAction(adminUser, user *user.User, action www.UserManageActionT, reasonForAction string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v,%v",
		www.UserManageAction[action], user.ID, user.Username, reasonForAction))
}

// logAdminProposalAction logs an admin action on a proposal.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) logAdminProposalAction(adminUser *user.User, token, action, reason string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v", action, token, reason))
}

// processManageUser processes the admin ManageUser command.
func (p *politeiawww) processManageUser(mu *www.ManageUser, adminUser *user.User) (*www.ManageUserReply, error) {
	// Fetch the database user.
	user, err := p.getUserByIDStr(mu.UserID)
	if err != nil {
		return nil, err
	}

	// Validate that the action is valid.
	if mu.Action == www.UserManageInvalid {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUserManageAction,
		}
	}

	// Validate that the reason is supplied.
	mu.Reason = strings.TrimSpace(mu.Reason)
	if len(mu.Reason) == 0 {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		}
	}

	// -168 hours is 7 days in the past
	expiredTime := time.Now().Add(-168 * time.Hour).Unix()

	switch mu.Action {
	case www.UserManageExpireNewUserVerification:
		user.NewUserVerificationExpiry = expiredTime
		user.ResendNewUserVerificationExpiry = expiredTime
	case www.UserManageExpireUpdateKeyVerification:
		user.UpdateKeyVerificationExpiry = expiredTime
	case www.UserManageExpireResetPasswordVerification:
		user.ResetPasswordVerificationExpiry = expiredTime
	case www.UserManageClearUserPaywall:
		p.removeUsersFromPool([]uuid.UUID{user.ID}, paywallTypeUser)
		user.NewUserPaywallAmount = 0
		user.NewUserPaywallTx = "cleared_by_admin"
		user.NewUserPaywallPollExpiry = 0
	case www.UserManageUnlock:
		user.FailedLoginAttempts = 0
	case www.UserManageDeactivate:
		user.Deactivated = true
	case www.UserManageReactivate:
		user.Deactivated = false
	default:
		return nil, fmt.Errorf("unsupported user edit action: %v",
			www.UserManageAction[mu.Action])
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

	return &www.ManageUserReply{}, nil
}

// userByPubKey fetches a user by public key
func (p *politeiawww) userByPubKey(pubkey string) (*user.User, error) {
	id, ok := p.getUserIDByPubKey(pubkey)
	if ok {
		return p.getUserByIDStr(id)
	}
	return nil, user.ErrUserNotFound
}

// processUsers returns a list of users given a set of filters. Admins can
// search by pubkey, username or email. Username and email searches will
// return partial matches. Pubkey searches must be an exact match. Non admins
// can search by pubkey or username. Non admin searches will only return exact
// matches.
func (p *politeiawww) processUsers(users *www.Users, isAdmin bool) (*www.UsersReply, error) {
	log.Tracef("processUsers: %v", isAdmin)

	emailQuery := strings.ToLower(users.Email)
	usernameQuery := formatUsername(users.Username)
	pubkeyQuery := users.PublicKey

	var u *user.User
	var totalUsers uint64
	var totalMatches uint64
	var pubkeyMatchID string
	matchedUsers := make([]www.AbridgedUser, 0, www.UserListPageSize)

	if pubkeyQuery != "" {
		// Search by pubkey. Only exact matches are returned.
		// Validate pubkey
		_, err := validatePubkey(pubkeyQuery)
		if err != nil {
			return nil, err
		}

		u, err = p.userByPubKey(pubkeyQuery)
		if err != nil {
			if err == user.ErrUserNotFound {
				// Pubkey searches require an exact match. If no
				// match was found, we can go ahead and return.
				return &www.UsersReply{}, nil
			}
			return nil, err
		}

		pubkeyMatchID = u.ID.String()
	}

	switch {
	case isAdmin:
		// Admins can search by username and/or email with
		// partial matches being returned.
		err := p.db.AllUsers(func(user *user.User) {
			totalUsers++
			userMatches := true

			// If both emailQuery and usernameQuery are non-empty, the
			// user must match both to be included in the results.
			if emailQuery != "" {
				if !strings.Contains(strings.ToLower(user.Email),
					emailQuery) {
					userMatches = false
				}
			}

			if usernameQuery != "" && userMatches {
				if !strings.Contains(strings.ToLower(user.Username),
					usernameQuery) {
					userMatches = false
				}
			}

			if pubkeyQuery != "" && userMatches {
				if user.ID.String() != pubkeyMatchID {
					userMatches = false
				}
			}

			if userMatches {
				totalMatches++
				if totalMatches < www.UserListPageSize {
					matchedUsers = append(matchedUsers, www.AbridgedUser{
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
		sort.Slice(matchedUsers, func(i, j int) bool {
			return matchedUsers[i].Username < matchedUsers[j].Username
		})

	default:
		// Non-admins can search by username and the search
		// must be an exact match.
		if usernameQuery != "" {
			// Validate username
			err := validateUsername(usernameQuery)
			if err != nil {
				return nil, err
			}

			u, err = p.db.UserGetByUsername(usernameQuery)
			if err != nil {
				// ErrUserNotFound is ok. Empty search results
				// will be returned.
				if err != user.ErrUserNotFound {
					return nil, err
				}
			}

			// If both pubkeyQuery and usernameQuery are non-empty, the
			// user must match both to be included in the results.
			if (u != nil) && (pubkeyQuery != "") &&
				(u.ID.String() != pubkeyMatchID) {
				// User doesn't match both
				u = nil
			}
		}

		if u != nil {
			totalMatches++
			matchedUsers = append(matchedUsers, www.AbridgedUser{
				ID:       u.ID.String(),
				Username: u.Username})
		}
	}

	return &www.UsersReply{
		TotalUsers:   totalUsers,
		TotalMatches: totalMatches,
		Users:        matchedUsers,
	}, nil
}

// processUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (p *politeiawww) processUserPaymentsRescan(upr www.UserPaymentsRescan) (*www.UserPaymentsRescanReply, error) {
	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &www.UserPaymentsRescanReply{}, nil
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
		newCreditsWWW[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &www.UserPaymentsRescanReply{
		NewCredits: newCreditsWWW,
	}, nil
}

// processVerifyUserPayment verifies that the provided transaction
// meets the minimum requirements to mark the user as paid, and then does
// that in the user database.
func (p *politeiawww) processVerifyUserPayment(u *user.User, vupt www.VerifyUserPayment) (*www.VerifyUserPaymentReply, error) {
	var reply www.VerifyUserPaymentReply
	if p.HasUserPaid(u) {
		reply.HasPaid = true
		return &reply, nil
	}

	if paywallHasExpired(u.NewUserPaywallPollExpiry) {
		err := p.GenerateNewUserPaywall(u)
		if err != nil {
			return nil, err
		}
		reply.PaywallAddress = u.NewUserPaywallAddress
		reply.PaywallAmount = u.NewUserPaywallAmount
		reply.PaywallTxNotBefore = u.NewUserPaywallTxNotBefore
		return &reply, nil
	}

	tx, _, err := util.FetchTxWithBlockExplorers(u.NewUserPaywallAddress,
		u.NewUserPaywallAmount, u.NewUserPaywallTxNotBefore,
		p.cfg.MinConfirmationsRequired)
	if err != nil {
		if err == util.ErrCannotVerifyPayment {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusCannotVerifyPayment,
			}
		}
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

// removeUsersFromPool removes the provided user IDs from the the poll pool.
//
// Currently, updating the user db and removing the user from pool isn't an
// atomic operation.  This can lead to a scenario where the user has been
// marked as paid in the db, but has not yet been removed from the pool. If a
// user issues a proposal paywall during this time, the proposal paywall will
// replace the user paywall in the pool. When the pool proceeds to remove the
// user paywall, it will mistakenly remove the proposal paywall instead.
// Proposal credits will not be added to the user's account. The workaround
// until this code gets replaced with websockets is to pass in the paywallType
// when removing a pool member.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) removeUsersFromPool(userIDsToRemove []uuid.UUID, paywallType string) {
	p.Lock()
	defer p.Unlock()

	for _, userID := range userIDsToRemove {
		if p.userPaywallPool[userID].paywallType == paywallType {
			delete(p.userPaywallPool, userID)
		}
	}
}

// addUserToPaywallPool adds a database user to the paywall pool.
//
// This function must be called WITH the mutex held.
func (p *politeiawww) addUserToPaywallPool(u *user.User, paywallType string) {
	p.userPaywallPool[u.ID] = paywallPoolMember{
		paywallType: paywallType,
		address:     u.NewUserPaywallAddress,
		amount:      u.NewUserPaywallAmount,
		txNotBefore: u.NewUserPaywallTxNotBefore,
		pollExpiry:  u.NewUserPaywallPollExpiry,
	}
}

// addUserToPaywallPoolLock adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) addUserToPaywallPoolLock(u *user.User, paywallType string) {
	if !p.paywallIsEnabled() {
		return
	}

	p.Lock()
	defer p.Unlock()

	p.addUserToPaywallPool(u, paywallType)
}

// addUsersToPaywallPool adds a user and its paywall info to the in-memory pool.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) addUsersToPaywallPool() error {
	p.Lock()
	defer p.Unlock()

	// Create the in-memory pool of all users who need to pay the paywall.
	err := p.db.AllUsers(func(u *user.User) {
		// Proposal paywalls
		if p.userHasValidProposalPaywall(u) {
			p.addUserToPaywallPool(u, paywallTypeProposal)
			return
		}

		// User paywalls
		if p.HasUserPaid(u) {
			return
		}
		if u.NewUserVerificationToken != nil {
			return
		}
		if paywallHasExpired(u.NewUserPaywallPollExpiry) {
			return
		}

		p.addUserToPaywallPool(u, paywallTypeUser)
	})
	if err != nil {
		return err
	}

	log.Tracef("Adding %v users to paywall pool", len(p.userPaywallPool))
	return nil
}

// updateUserAsPaid records in the database that the user has paid.
func (p *politeiawww) updateUserAsPaid(u *user.User, tx string) error {
	u.NewUserPaywallTx = tx
	u.NewUserPaywallPollExpiry = 0
	return p.db.UserUpdate(*u)
}

// derivePaywallInfo derives a new paywall address for the user.
func (p *politeiawww) derivePaywallInfo(u *user.User) (string, uint64, int64, error) {
	address, err := util.DerivePaywallAddress(p.params,
		p.cfg.PaywallXpub, uint32(u.PaywallAddressIndex))
	if err != nil {
		err = fmt.Errorf("Unable to derive paywall address #%v "+
			"for %v: %v", u.ID.ID(), u.Email, err)
	}

	return address, p.cfg.PaywallAmount, time.Now().Unix(), err
}

// createUserPaywallPoolCopy returns a map of the poll pool.
//
// This function must be called WITHOUT the mutex held.
func (p *politeiawww) createUserPaywallPoolCopy() map[uuid.UUID]paywallPoolMember {
	p.RLock()
	defer p.RUnlock()

	poolCopy := make(map[uuid.UUID]paywallPoolMember, len(p.userPaywallPool))

	for k, v := range p.userPaywallPool {
		poolCopy[k] = v
	}

	return poolCopy
}

// checkForUserPayments is called periodically to see if payments have come
// through.
func (p *politeiawww) checkForUserPayments(pool map[uuid.UUID]paywallPoolMember) (bool, []uuid.UUID) {
	var userIDsToRemove []uuid.UUID

	for userID, poolMember := range pool {
		u, err := p.db.UserGetById(userID)
		if err != nil {
			if err == user.ErrShutdown {
				// The database is shutdown, so stop the
				// thread.
				return false, nil
			}

			log.Errorf("cannot fetch user by id %v: %v\n",
				userID, err)
			continue
		}

		if poolMember.paywallType != paywallTypeUser {
			continue
		}

		log.Tracef("Checking the user paywall address for user %v...",
			u.Email)

		if p.HasUserPaid(u) {
			// The user could have been marked as paid by
			// RouteVerifyUserPayment, so just remove him from the
			// in-memory pool.
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, user already paid")
			continue
		}

		if paywallHasExpired(u.NewUserPaywallPollExpiry) {
			userIDsToRemove = append(userIDsToRemove, userID)
			log.Tracef("  removing from polling, poll has expired")
			continue
		}

		tx, _, err := util.FetchTxWithBlockExplorers(poolMember.address,
			poolMember.amount, poolMember.txNotBefore,
			p.cfg.MinConfirmationsRequired)
		if err != nil {
			log.Errorf("cannot fetch tx: %v\n", err)
			continue
		}

		if tx != "" {
			// Update the user in the database.
			err = p.updateUserAsPaid(u, tx)
			if err != nil {
				if err == user.ErrShutdown {
					// The database is shutdown, so stop
					// the thread.
					return false, nil
				}

				log.Errorf("cannot update user with id %v: %v",
					u.ID, err)
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

// GenerateNewUserPaywall generates new paywall info, if necessary, and saves
// it in the database.
func (p *politeiawww) GenerateNewUserPaywall(u *user.User) error {
	// Check that the paywall is enabled.
	if !p.paywallIsEnabled() {
		return nil
	}

	// Check that the user either hasn't had paywall information set yet,
	// or it has expired.
	if u.NewUserPaywallAddress != "" &&
		!paywallHasExpired(u.NewUserPaywallPollExpiry) {
		return nil
	}

	if u.NewUserPaywallAddress == "" {
		address, amount, txNotBefore, err := p.derivePaywallInfo(u)
		if err != nil {
			return err
		}

		u.NewUserPaywallAddress = address
		u.NewUserPaywallAmount = amount
		u.NewUserPaywallTxNotBefore = txNotBefore
	}
	u.NewUserPaywallPollExpiry = time.Now().Add(paywallExpiryDuration).Unix()

	err := p.db.UserUpdate(*u)
	if err != nil {
		return err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeUser)
	return nil
}

// HasUserPaid checks that a user has paid the paywall
func (p *politeiawww) HasUserPaid(u *user.User) bool {
	// Return true if paywall is disabled
	if !p.paywallIsEnabled() {
		return true
	}

	return u.NewUserPaywallTx != ""
}

// initPaywallCheck is intended to be called
func (p *politeiawww) initPaywallChecker() error {
	if p.cfg.PaywallAmount == 0 {
		// Paywall not configured.
		return nil
	}

	err := p.addUsersToPaywallPool()
	if err != nil {
		return err
	}

	// Start the thread that checks for payments.
	go p.checkForPayments()
	return nil
}

func setInviteNewUserVerification(u *user.User, token []byte, expiry int64, includeResend bool) {
	u.NewUserVerificationToken = token
	u.NewUserVerificationExpiry = expiry
	if includeResend {
		// This field is used to support requesting another registration email
		// quickly, without having to wait the full email-spam-prevention
		// period.
		u.ResendNewUserVerificationExpiry = expiry
	}
}

func setRegisterUserIdentity(u *user.User, token []byte, expiry int64, includeResend bool) {
	u.NewUserVerificationToken = token
	u.NewUserVerificationExpiry = expiry
	if includeResend {
		// This field is used to support requesting another registration email
		// quickly, without having to wait the full email-spam-prevention
		// period.
		u.ResendNewUserVerificationExpiry = expiry
	}
}

// processInviteNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a InviteNewUserReply.  The caller shall
// verify error and determine how to return this information upstream.
func (p *politeiawww) processInviteNewUser(u cms.InviteNewUser) (*www.NewUserReply, error) {
	var (
		reply  www.NewUserReply
		token  []byte
		expiry int64
	)

	// Validate email
	if !validEmail.MatchString(u.Email) {
		log.Debugf("processInviteNewUser: invalid email '%v'", u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedEmail,
		}
	}

	existingUser, err := p.userByEmail(u.Email)
	if err == nil {
		// Check if the user is already verified.
		if existingUser.NewUserVerificationToken == nil {
			return &reply, nil
		}
	}

	// Generate the verification token and expiry.
	token, expiry, err = generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Create a new database user with the provided information.
	// This temporarily sets the username to the given email, which will be
	// overwritten during registration.  This is needed since the constraints
	// on the cockroachdb for usernames requires there to be no duplicates.
	// Previously, if unset, the username of "" would cause a duplicate error
	// to be thrown during db migration.
	newUser := user.User{
		Email:    strings.ToLower(u.Email),
		Username: strings.ToLower(u.Email),
		Admin:    false,
	}
	setInviteNewUserVerification(&newUser, token, expiry, false)

	if !p.test {
		// Try to email the verification link first; if it fails, then
		// the new user won't be created.
		//
		// This is conditional on the email server being setup.
		err := p.emailInviteNewUserVerificationLink(u.Email, hex.EncodeToString(token))
		if err != nil {
			log.Errorf("Email invite new user verification link failed %v, %v", u.Email, err)
			return &reply, nil
		}
	}

	// Check if the user already exists.
	if existingUser != nil {
		// Update the user in the db. Which will resend the email and give a new token
		newUser.ID = existingUser.ID
		err = p.db.UserUpdate(newUser)
		if err != nil {
			return nil, err
		}
	} else {
		// Save the new user in the db.
		err = p.db.UserNew(newUser)
		if err != nil {
			return nil, err
		}

		// Update user emails cache. The user ID needs to be
		// looked up first.
		u, err := p.db.UserGetByUsername(newUser.Username)
		if err != nil {
			return nil, fmt.Errorf("userByUsername '%v': %v",
				newUser.Username, err)
		}

		p.setUserEmails(u.Email, u.ID)
	}

	reply.VerificationToken = hex.EncodeToString(token)
	return &reply, nil
}

func (p *politeiawww) processRegisterUser(u cms.RegisterUser) (*cms.RegisterUserReply, error) {
	var reply cms.RegisterUserReply

	// Check that the user already exists.
	existingUser, err := p.userByEmail(u.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("RegisterUser failure for %v: user not found",
				u.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Format and validate the username.
	username := formatUsername(u.Username)
	err = validateUsername(username)
	if err != nil {
		return nil, err
	}

	// Ensure username is unique.
	_, err = p.db.UserGetByUsername(u.Username)
	switch err {
	case nil:
		// Duplicate username
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Username doesn't exist; continue
	default:
		return nil, err
	}

	// Validate the password.
	err = validatePassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(u.PublicKey, existingUser)
	if err != nil {
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		log.Debugf("Register failure for %v: verification token could "+
			"not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, existingUser.NewUserVerificationToken) {
		log.Debugf("Register failure for %v: verification token doesn't "+
			"match, expected %v", u.Email, existingUser.NewUserVerificationToken)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if time.Now().Unix() > existingUser.NewUserVerificationExpiry {
		log.Debugf("Register failure for %v: verification token expired",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Create a new database user with the provided information.
	newUser := user.User{
		ID:                        existingUser.ID,
		Email:                     strings.ToLower(u.Email),
		Username:                  username,
		HashedPassword:            hashedPassword,
		Admin:                     false,
		NewUserVerificationToken:  nil,
		NewUserVerificationExpiry: 0,
	}

	// Set the newUser's identity with the provided public key
	newUser.Identities = []user.Identity{{
		Activated: time.Now().Unix(),
	}}
	copy(newUser.Identities[0].Key[:], pk)

	// Update the user in the db.
	err = p.db.UserUpdate(newUser)
	if err != nil {
		return nil, err
	}

	// Even if user is non-nil, this will bring it up-to-date
	// with the new information inserted via newUser.
	existingUser, err = p.userByEmail(newUser.Email)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve account info for %v: %v",
			newUser.Email, err)
	}

	// Associate the user id with the new public key.
	p.setUserPubkeyAssociaton(existingUser, u.PublicKey)

	err = p.db.UserUpdate(newUser)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
