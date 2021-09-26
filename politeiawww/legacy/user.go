// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	LoginAttemptsToLockUser = 5

	// Number of attempts until totp locks until the next window
	totpFailedAttempts = 2

	// Route to reset password at GUI
	ResetPasswordGuiRoute = "/password" // XXX what is this doing here?

	emailRegex = `^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

var (
	validUsername = regexp.MustCompile(createUsernameRegex())
	validEmail    = regexp.MustCompile(emailRegex)

	// resetPasswordMinWaitTime is the minimum amount of time to wait
	// before sending a response back to the client for the reset
	// password route. This is done to prevent an attacker from being
	// able to execute a timing attack to determine if the provided
	// email address is the user's valid email address.
	resetPasswordMinWaitTime = 500 * time.Millisecond

	// loginMinWaitTime is the minimum amount of time to wait before
	// the server sends a response to the client for the login route.
	// This is done to prevent an attacker from being able to execute
	// a timing attack to determine whether the ErrorStatusInvalidLogin
	// response is specific to a bad email or a bad password.
	loginMinWaitTime = 500 * time.Millisecond
)

// handleSecret is a mock handler to test privileged routes.
func (p *LegacyPoliteiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSecret")

	fmt.Fprintf(w, "secret sauce")
}

// handleNewUser handles the incoming new user command. It verifies that the
// new user doesn't already exist, and then creates a new user in the db and
// generates a random code used for verification. The code is intended to be
// sent to the specified email.
func (p *LegacyPoliteiawww) handleNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewUser")

	// Get the new user command.
	var u www.NewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleNewUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processNewUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleNewUser: processNewUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleVerifyNewUser handles the incoming new user verify command. It
// verifies that the user with the provided email has a verification token that
// matches the provided token and that the verification token has not yet
// expired.
func (p *LegacyPoliteiawww) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyNewUser")

	// Get the new user verify command.
	var vnu www.VerifyNewUser
	err := util.ParseGetParams(r, &vnu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyNewUser: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	_, err = p.processVerifyNewUser(vnu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyNewUser: "+
			"processVerifyNewUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, www.VerifyNewUserReply{})
}

// handleResendVerification sends another verification email for new user
// signup, if there is an existing verification token and it is expired.
func (p *LegacyPoliteiawww) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleResendVerification")

	// Get the resend verification command.
	var rv www.ResendVerification
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rv); err != nil {
		RespondWithError(w, r, 0, "handleResendVerification: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	rvr, err := p.processResendVerification(&rv)
	if err != nil {
		var usrErr www.UserError
		if errors.As(err, &usrErr) {
			switch usrErr.ErrorCode {
			case www.ErrorStatusUserNotFound, www.ErrorStatusEmailAlreadyVerified,
				www.ErrorStatusVerificationTokenUnexpired:
				// We do not return these errors because we do not want
				// the caller to be able to ascertain whether an email
				// address has an acount.
				util.RespondWithJSON(w, http.StatusOK, &www.ResendVerificationReply{})
				return
			}
		}

		RespondWithError(w, r, 0, "handleResendVerification: "+
			"processResendVerification %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, *rvr)
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *LegacyPoliteiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLogin")

	// Get the login command.
	var l www.Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&l); err != nil {
		RespondWithError(w, r, 0, "handleLogin: failed to decode: %v",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processLogin(l)
	if err != nil {
		RespondWithError(w, r, http.StatusUnauthorized,
			"handleLogin: processLogin: %v", err)
		return
	}

	// Initialize a session for the logged in user
	err = p.sessions.NewSession(w, r, reply.UserID)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogin: initSession: %v", err)
		return
	}

	// Set session max age
	reply.SessionMaxAge = sessions.SessionMaxAge

	// Reply with the user information.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLogout logs the user out.
func (p *LegacyPoliteiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLogout")

	_, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleLogout: getSessionUser", www.UserError{
			ErrorCode: www.ErrorStatusNotLoggedIn,
		})
		return
	}

	err = p.sessions.DelSession(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogout: removeSession %v", err)
		return
	}

	// Reply with the user information.
	var reply www.LogoutReply
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleMe returns logged in user information.
func (p *LegacyPoliteiawww) handleMe(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleMe")

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: getSessionUser %v", err)
		return
	}

	reply, err := p.createLoginReply(user, user.LastLoginTime)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: createLoginReply %v", err)
		return
	}

	// Set session max age
	reply.SessionMaxAge = sessions.SessionMaxAge

	util.RespondWithJSON(w, http.StatusOK, *reply)
}

// handleResetPassword handles the reset password command.
func (p *LegacyPoliteiawww) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	log.Trace("handleResetPassword")

	// Get the reset password command.
	var rp www.ResetPassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rp); err != nil {
		RespondWithError(w, r, 0, "handleResetPassword: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	rpr, err := p.processResetPassword(rp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleResetPassword: processResetPassword %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, rpr)
}

// handleVerifyResetPassword handles the verify reset password command.
func (p *LegacyPoliteiawww) handleVerifyResetPassword(w http.ResponseWriter, r *http.Request) {
	log.Trace("handleVerifyResetPassword")

	var vrp www.VerifyResetPassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vrp); err != nil {
		RespondWithError(w, r, 0, "handleVerifyResetPassword: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processVerifyResetPassword(vrp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyResetPassword: processVerifyResetPassword %v", err)
		return
	}

	// Delete all existing sessions for the user. Return a 200 if
	// either of these calls fail since the password was verified
	// correctly.
	user, err := p.db.UserGetByUsername(vrp.Username)
	if err != nil {
		log.Errorf("handleVerifyResetPassword: UserGetByUsername(%v): %v",
			vrp.Username, err)
		util.RespondWithJSON(w, http.StatusOK, reply)
		return
	}
	err = p.db.SessionsDeleteByUserID(user.ID, []string{})
	if err != nil {
		log.Errorf("handleVerifyResetPassword: SessionsDeleteByUserID(%v, %v): %v",
			user.ID, []string{}, err)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserDetails handles fetching user details by user id.
func (p *LegacyPoliteiawww) handleUserDetails(w http.ResponseWriter, r *http.Request) {
	// Add the path param to the struct.
	log.Tracef("handleUserDetails")
	pathParams := mux.Vars(r)
	var ud www.UserDetails
	ud.UserID = pathParams["userid"]

	userID, err := uuid.Parse(ud.UserID)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserDetails: ParseUint",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get session user. This is a public route so one might not exist.
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil && !errors.Is(err, sessions.ErrSessionNotFound) {
		RespondWithError(w, r, 0,
			"handleUserDetails: getSessionUser %v", err)
		return
	}

	udr, err := p.processUserDetails(&ud,
		user != nil && user.ID == userID,
		user != nil && user.Admin,
	)

	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserDetails: processUserDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, udr)
}

// handleEditUser handles editing a user's preferences.
func (p *LegacyPoliteiawww) handleEditUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleEditUser")

	var eu www.EditUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&eu); err != nil {
		RespondWithError(w, r, 0, "handleEditUser: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	adminUser, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleEditUser: getSessionUser %v",
			err)
		return
	}

	eur, err := p.processEditUser(&eu, adminUser)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditUser: processEditUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, eur)
}

// handleUpdateUserKey handles the incoming update user key command. It
// generates a random code used for verification. The code is intended to be
// sent to the email of the logged in user.
func (p *LegacyPoliteiawww) handleUpdateUserKey(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUpdateUserKey")

	// Get the update user key command.
	var u www.UpdateUserKey
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleUpdateUserKey: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUpdateUserKey: getSessionUser %v", err)
		return
	}

	reply, err := p.processUpdateUserKey(user, u)
	if err != nil {
		RespondWithError(w, r, 0, "handleUpdateUserKey: processUpdateUserKey %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleVerifyUpdateUserKey handles the incoming update user key verify
// command. It verifies that the user with the provided email has a
// verification token that matches the provided token and that the verification
// token has not yet expired.
func (p *LegacyPoliteiawww) handleVerifyUpdateUserKey(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyUpdateUserKey")

	// Get the new user verify command.
	var vuu www.VerifyUpdateUserKey
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vuu); err != nil {
		RespondWithError(w, r, 0, "handleVerifyUpdateUserKey: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUpdateUserKey: getSessionUser %v", err)
		return
	}

	_, err = p.processVerifyUpdateUserKey(user, vuu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyUpdateUserKey: "+
			"processVerifyUpdateUserKey %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, www.VerifyUpdateUserKeyReply{})
}

// handleChangeUsername handles the change user name command.
func (p *LegacyPoliteiawww) handleChangeUsername(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleChangeUsername")

	// Get the change username command.
	var cu www.ChangeUsername
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cu); err != nil {
		RespondWithError(w, r, 0, "handleChangeUsername: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangeUsername: getSessionUser %v", err)
		return
	}

	reply, err := p.processChangeUsername(user.Email, cu)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangeUsername: processChangeUsername %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleChangePassword handles the change password command.
func (p *LegacyPoliteiawww) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleChangePassword")

	// Get the change password command.
	var cp www.ChangePassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cp); err != nil {
		RespondWithError(w, r, 0, "handleChangePassword: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	session, err := p.sessions.GetSession(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: getSession %v", err)
		return
	}
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: getSessionUser %v", err)
		return
	}

	reply, err := p.processChangePassword(user.Email, cp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: processChangePassword %v", err)
		return
	}

	// Delete all existing sessions for the user except the current.
	// Return a 200 if this call fails since the password was changed
	// correctly.
	err = p.db.SessionsDeleteByUserID(user.ID, []string{session.ID})
	if err != nil {
		log.Errorf("handleChangePassword: SessionsDeleteByUserID(%v, %v): %v",
			user.ID, []string{session.ID}, err)
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUsers handles fetching a list of users.
func (p *LegacyPoliteiawww) handleUsers(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUsers")

	var u www.Users
	err := util.ParseGetParams(r, &u)
	if err != nil {
		RespondWithError(w, r, 0, "handleUsers: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get session user. This is a public route so one might not exist.
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil && !errors.Is(err, sessions.ErrSessionNotFound) {
		RespondWithError(w, r, 0,
			"handleUsers: getSessionUser %v", err)
		return
	}

	isAdmin := (user != nil && user.Admin)
	ur, err := p.processUsers(&u, isAdmin)

	if err != nil {
		RespondWithError(w, r, 0,
			"handleUsers: processUsers %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleManageUser handles editing a user's details.
func (p *LegacyPoliteiawww) handleManageUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleManageUser")

	var mu www.ManageUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&mu); err != nil {
		RespondWithError(w, r, 0, "handleManageUser: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	adminUser, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleManageUser: getSessionUser %v",
			err)
		return
	}

	mur, err := p.processManageUser(&mu, adminUser)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleManageUser: processManageUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, mur)
}

// processNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply. The caller shall
// verify error and determine how to return this information upstream.
func (p *LegacyPoliteiawww) processNewUser(nu www.NewUser) (*www.NewUserReply, error) {
	log.Tracef("processNewUser: %v", nu.Username)

	// Format and validate user credentials
	nu.Email = strings.ToLower(nu.Email)
	if !validEmail.MatchString(nu.Email) {
		log.Debugf("processNewUser: invalid email '%v'", nu.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedEmail,
		}
	}
	err := validatePubKey(nu.PublicKey)
	if err != nil {
		return nil, err
	}

	nu.Username = formatUsername(nu.Username)
	err = validateUsername(nu.Username)
	if err != nil {
		return nil, err
	}

	// The client should be hashing the password before
	// sending it to politeiawww. This validation is only
	// relevant if the client failed to hash the password
	// or does not include a password in the request.
	err = validatePassword(nu.Password)
	if err != nil {
		return nil, err
	}

	// Check if user already exists
	u, err := p.userByEmail(nu.Email)
	switch err {
	case nil:
		// User exists

		// Return if the user is already verified
		if u.NewUserVerificationToken == nil {
			log.Debugf("processNewUser: '%v' already verified",
				nu.Username)
			return &www.NewUserReply{}, nil
		}

		// User is not already verified. Check if the verification token
		// has expired. If the token has not expired yet, we simply return.
		// The user will have to wait until the token expires before a
		// new one will be sent. If the token has expired, we update the
		// user in the database and send the user a new token. The user
		// identity will be updated if the request specifies a new public
		// key.
		if u.NewUserVerificationExpiry > time.Now().Unix() {
			log.Debugf("processNewUser: '%v' not verified, "+
				"token not expired", nu.Username)
			return &www.NewUserReply{}, nil
		}

		// Ensure public key is unique
		usr, err := p.db.UserGetByPubKey(nu.PublicKey)
		if err != nil {
			if errors.Is(err, user.ErrUserNotFound) {
				// Pubkey is unique, but is not the same pubkey that
				// the user originally signed up with. This is fine.
				// The user's identity just needs to be updated.
				id, err := user.NewIdentity(nu.PublicKey)
				if err != nil {
					return nil, err
				}
				err = u.AddIdentity(*id)
				if err != nil {
					return nil, err
				}
			}
		} else {
			switch {
			case usr.ID.String() == u.ID.String():
				// Pubkey exists and belongs to this user. This is
				// ok. It just means that the user is requesting a
				// new verification token using the same identity
				// that they signed up with. Continue.
			default:
				// Pubkey exists and belongs to another user
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusDuplicatePublicKey,
				}
			}
		}

		// Generate a new verification token
		tokenb, expiry, err := newVerificationTokenAndExpiry()
		if err != nil {
			return nil, err
		}

		// Email the verification token before updating the
		// database. If the email fails, the database won't
		// be updated.
		err = p.emailUserEmailVerify(u.Email,
			hex.EncodeToString(tokenb), u.Username)
		if err != nil {
			log.Errorf("processNewUser: mail verification "+
				"token failed for '%v': %v", u.Email, err)
			return &www.NewUserReply{}, nil
		}

		// Update user record with the verification token and
		// the new identity if one was set.
		u.NewUserVerificationToken = tokenb
		u.NewUserVerificationExpiry = expiry
		err = p.db.UserUpdate(*u)
		if err != nil {
			return nil, err
		}

		// Send reply. Only return the verification token in
		// the reply if the mail server has been disabled.
		var t string
		if !p.mail.IsEnabled() {
			t = hex.EncodeToString(u.NewUserVerificationToken)
		}
		return &www.NewUserReply{
			VerificationToken: t,
		}, nil
	case user.ErrUserNotFound:
		// User doesn't exist; continue
	default:
		// All other errors
		return nil, err
	}

	// User does not exist. Create a new user.

	// Ensure username is unique
	_, err = p.db.UserGetByUsername(nu.Username)
	switch err {
	case nil:
		// Duplicate username
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Username does not exist; continue
	default:
		return nil, err
	}

	// Ensure public key is unique
	_, err = p.db.UserGetByPubKey(nu.PublicKey)
	switch err {
	case user.ErrUserNotFound:
		// Pubkey is unique; continue
	case nil:
		// Duplicate pubkey
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicatePublicKey,
		}
	default:
		// All other errors
		return nil, err
	}

	// Create user
	hashedPass, err := p.hashPassword(nu.Password)
	if err != nil {
		return nil, err
	}
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}
	newUser := user.User{
		Email:                     nu.Email,
		Username:                  nu.Username,
		HashedPassword:            hashedPass,
		NewUserVerificationToken:  tokenb,
		NewUserVerificationExpiry: expiry,
	}
	id, err := user.NewIdentity(nu.PublicKey)
	if err != nil {
		return nil, err
	}
	err = newUser.AddIdentity(*id)
	if err != nil {
		return nil, err
	}

	// Try to email the verification link first; if it fails,
	// then the new user won't be created.
	//
	// This is conditional on the email server being setup.
	err = p.emailUserEmailVerify(newUser.Email,
		hex.EncodeToString(tokenb), newUser.Username)
	if err != nil {
		log.Errorf("processNewUser: mail verification token "+
			"failed for '%v': %v", newUser.Email, err)
		return &www.NewUserReply{}, nil
	}

	// Save new user to the database
	err = p.db.UserNew(newUser)
	if err != nil {
		return nil, err
	}

	// Set paywall info for the user. This had to wait until after the
	// user was already created in the db because the db sets the
	// paywall address index when the user is created, and the paywall
	// address index is used to generate the paywall info. Lookup the
	// user from the db to get the paywall address index.
	u, err = p.db.UserGetByUsername(newUser.Username)
	if err != nil {
		return nil, err
	}
	err = p.generateNewUserPaywall(u)
	if err != nil {
		return nil, err
	}

	// Update memory cache
	p.setUserEmailsCache(u.Email, u.ID)

	log.Infof("New user created: %v", u.Username)

	// Only return the verification token in the reply
	// if the mail server has been disabled.
	var t string
	if !p.mail.IsEnabled() {
		t = hex.EncodeToString(u.NewUserVerificationToken)
	}
	return &www.NewUserReply{
		VerificationToken: t,
	}, nil
}

// processVerifyNewUser verifies the token generated for a recently created
// user.  It ensures that the token matches with the input and that the token
// hasn't expired.  On success it returns database user record.
func (p *LegacyPoliteiawww) processVerifyNewUser(usr www.VerifyNewUser) (*user.User, error) {
	// Check that the user already exists.
	u, err := p.userByEmail(usr.Email)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
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
	id := u.InactiveIdentity()
	if id == nil {
		log.Debugf("VerifyNewUser failure for %v: no public key",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	pi, err := identity.PublicIdentityFromBytes(id.Key[:])
	if err != nil {
		return nil, err
	}
	if !pi.VerifyMessage([]byte(usr.VerificationToken), sig) {
		log.Debugf("VerifyNewUser failure for %v: signature doesn't match "+
			"(pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Clear out the verification token fields
	// and activate the identity for the user.
	u.NewUserVerificationToken = nil
	u.NewUserVerificationExpiry = 0
	u.ResendNewUserVerificationExpiry = 0
	err = u.ActivateIdentity(id.Key[:])
	if err != nil {
		return nil, err
	}
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeUser)

	return u, nil
}

// processResendVerification resends a new user verification email if the
// user exists and his verification token is expired.
func (p *LegacyPoliteiawww) processResendVerification(rv *www.ResendVerification) (*www.ResendVerificationReply, error) {
	rvr := www.ResendVerificationReply{}

	// Get user from db.
	u, err := p.userByEmail(rv.Email)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
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
	err = validatePubKey(rv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Ensure the pubkey is unique
	_, err = p.db.UserGetByPubKey(rv.PublicKey)
	switch err {
	case user.ErrUserNotFound:
	// Pubkey is unique; continue
	case nil:
		// Pubkey is not unique. The user is allowed to use the
		// same pubkey that they originally signed up with, so
		// only throw an error if the pubkey is not the user's
		// inactive identity pubkey.
		if u.InactiveIdentity().String() != rv.PublicKey {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			}
		}
	default:
		// All other errors
		return nil, err
	}

	// Set a new verificaton token and identity.
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}
	u.NewUserVerificationToken = token
	u.NewUserVerificationExpiry = expiry
	u.ResendNewUserVerificationExpiry = expiry
	id, err := user.NewIdentity(rv.PublicKey)
	if err != nil {
		return nil, err
	}
	err = u.AddIdentity(*id)
	if err != nil {
		return nil, err
	}

	// Try to email the verification link first; if it fails, then
	// the user won't be updated.
	//
	// This is conditional on the email server being setup.
	err = p.emailUserEmailVerify(u.Email,
		hex.EncodeToString(token), u.Username)
	if err != nil {
		log.Errorf("processResendVerification: email verification "+
			"token failed for '%v': %v", u.Email, err)
		return nil, err
	}

	// Update the user in the db.
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	// Only set the token if email verification is disabled.
	if !p.mail.IsEnabled() {
		rvr.VerificationToken = hex.EncodeToString(token)
	}
	return &rvr, nil
}

// processLogin logs the provided user into politeia. This is done using go
// routines in order to prevent timing attacks.
func (p *LegacyPoliteiawww) processLogin(l www.Login) (*www.LoginReply, error) {
	log.Tracef("processLogin: %v", l.Email)

	var (
		wg sync.WaitGroup
		ch = make(chan loginResult)
	)

	// Wait for both go routines to finish before returning the
	// reply. This is done to prevent an attacker from being able
	// to execute a timing attack to determine if the provided
	// email address is the user's valid email address.
	wg.Add(2)
	go func() {
		defer wg.Done()
		ch <- p.login(l)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(loginMinWaitTime)
	}()
	lr := <-ch
	wg.Wait()

	return lr.reply, lr.err
}

// processResetPassword is used to perform a password change when the user is
// not logged in. The provided email address must match the email address
// or the user record that corresponds to the provided username.
func (p *LegacyPoliteiawww) processResetPassword(rp www.ResetPassword) (*www.ResetPasswordReply, error) {
	log.Tracef("processResetPassword: %v", rp.Username)
	var (
		wg sync.WaitGroup
		ch = make(chan resetPasswordResult)
	)

	// Wait for both go routines to finish before returning the
	// reply. This is done to prevent an attacker from being able
	// to execute a timing attack to determine if the provided
	// email address is the user's valid email address.
	wg.Add(2)
	go func() {
		defer wg.Done()
		ch <- p.resetPassword(rp)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(resetPasswordMinWaitTime)
	}()
	rpr := <-ch
	wg.Wait()

	return &rpr.reply, rpr.err
}

// processVerifyResetPassword verifies the token that was sent to the user
// during the reset password command. If everything checks out, the user's
// password is updated with the provided new password and the user's account
// is unlocked if it had previously been locked.
func (p *LegacyPoliteiawww) processVerifyResetPassword(vrp www.VerifyResetPassword) (*www.VerifyResetPasswordReply, error) {
	log.Tracef("processVerifyResetPassword: %v %v",
		vrp.Username, vrp.VerificationToken)

	// Lookup user
	u, err := p.db.UserGetByUsername(vrp.Username)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return nil, err
	}

	// Validate verification token
	token, err := hex.DecodeString(vrp.VerificationToken)
	if err != nil {
		log.Debugf("processVerifyResetPassword: decode hex '%v': %v",
			vrp.VerificationToken, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}
	if !bytes.Equal(token, u.ResetPasswordVerificationToken) {
		log.Debugf("processVerifyResetPassword: wrong token: %v %v",
			hex.EncodeToString(token),
			hex.EncodeToString(u.ResetPasswordVerificationToken))
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}
	if u.ResetPasswordVerificationExpiry < time.Now().Unix() {
		log.Debugf("processVerifyResetPassword: token expired: %v %v",
			u.ResetPasswordVerificationExpiry, time.Now().Unix())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// The client should be hashing the password before sending
	// it to politeiawww. This validation is only relevant if the
	// client failed to hash the password or does not include a
	// password in the request.
	err = validatePassword(vrp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Hash the new password
	hashedPassword, err := p.hashPassword(vrp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Update the user
	u.ResetPasswordVerificationToken = nil
	u.ResetPasswordVerificationExpiry = 0
	u.HashedPassword = hashedPassword
	u.FailedLoginAttempts = 0

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return &www.VerifyResetPasswordReply{}, nil
}

// processUserDetails return the requested user's details. Some fields can be
// omitted or blank depending on the requester's access level.
func (p *LegacyPoliteiawww) processUserDetails(ud *www.UserDetails, isCurrentUser bool, isAdmin bool) (*www.UserDetailsReply, error) {
	// Fetch the database user.
	user, err := p.userByIDStr(ud.UserID)
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
func (p *LegacyPoliteiawww) processEditUser(eu *www.EditUser, user *user.User) (*www.EditUserReply, error) {
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

// processUpdateUserKey sets a verification token and expiry to allow the user
// to update his key pair; the token must be verified before it expires. If the
// token is already set and is expired, it generates a new one.
func (p *LegacyPoliteiawww) processUpdateUserKey(usr *user.User, uuk www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	// Ensure we got a proper pubkey that is unique.
	err := validatePubKey(uuk.PublicKey)
	if err != nil {
		return nil, err
	}
	_, err = p.db.UserGetByPubKey(uuk.PublicKey)
	switch err {
	case user.ErrUserNotFound:
		// Pubkey is unique; continue
	case nil:
		// Pubkey is not unique
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicatePublicKey,
		}
	default:
		// All other errors
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
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}
	usr.UpdateKeyVerificationToken = tokenb
	usr.UpdateKeyVerificationExpiry = expiry

	// Add inactive identity to the user
	id, err := user.NewIdentity(uuk.PublicKey)
	if err != nil {
		return nil, err
	}
	err = usr.AddIdentity(*id)
	if err != nil {
		return nil, err
	}

	// Email the user a verification link. The database does not get
	// updated if this fails.
	//
	// This is conditional on the email server being setup.
	token := hex.EncodeToString(tokenb)
	recipient := map[uuid.UUID]string{
		usr.ID: usr.Email,
	}
	err = p.emailUserKeyUpdate(usr.Username, uuk.PublicKey, token, recipient)
	if err != nil {
		return nil, err
	}

	// Save user changes to the database
	err = p.db.UserUpdate(*usr)
	if err != nil {
		return nil, err
	}

	// Only set the token if email verification is disabled.
	var t string
	if !p.mail.IsEnabled() {
		t = token
	}
	return &www.UpdateUserKeyReply{
		VerificationToken: t,
	}, nil
}

// processVerifyUpdateUserKey verifies the token generated for the recently
// generated key pair. It ensures that the token matches with the input and
// that the token hasn't expired.
func (p *LegacyPoliteiawww) processVerifyUpdateUserKey(u *user.User, vu www.VerifyUpdateUserKey) (*user.User, error) {
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

	id := u.InactiveIdentity()
	if id == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
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

	// Clear out the verification token fields in the db and activate
	// the key and deactivate the one it's replacing.
	u.UpdateKeyVerificationToken = nil
	u.UpdateKeyVerificationExpiry = 0
	err = u.ActivateIdentity(id.Key[:])
	if err != nil {
		return nil, err
	}

	return u, p.db.UserUpdate(*u)
}

// processChangeUsername checks that the password matches the one
// in the database, then checks that the username is valid and not
// already taken, then changes the user record in the database to
// the new username.
func (p *LegacyPoliteiawww) processChangeUsername(email string, cu www.ChangeUsername) (*www.ChangeUsernameReply, error) {
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
func (p *LegacyPoliteiawww) processChangePassword(email string, cp www.ChangePassword) (*www.ChangePasswordReply, error) {
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
			ErrorCode: www.ErrorStatusInvalidPassword,
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

	// We will also reset any possibly issued verification token to avoid
	// a small chance of one having been issued by a potential attacker.
	// Any update to the password by a logged in user, should be seen as
	// an authorized request and therefore override any potential request.
	u.ResetPasswordVerificationToken = nil
	u.ResetPasswordVerificationExpiry = 0

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	recipient := map[uuid.UUID]string{
		u.ID: u.Email,
	}
	err = p.emailUserPasswordChanged(u.Username, recipient)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// processUsers returns a list of users given a set of filters. Admins can
// search by pubkey, username or email. Username and email searches will
// return partial matches. Pubkey searches must be an exact match. Non admins
// can search by pubkey or username. Non admin searches will only return exact
// matches.
func (p *LegacyPoliteiawww) processUsers(users *www.Users, isAdmin bool) (*www.UsersReply, error) {
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
		err := validatePubKey(pubkeyQuery)
		if err != nil {
			return nil, err
		}

		u, err = p.db.UserGetByPubKey(pubkeyQuery)
		if err != nil {
			if errors.Is(err, user.ErrUserNotFound) {
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
				if !errors.Is(err, user.ErrUserNotFound) {
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

// processManageUser processes the admin ManageUser command.
func (p *LegacyPoliteiawww) processManageUser(mu *www.ManageUser, adminUser *user.User) (*www.ManageUserReply, error) {
	// Fetch the database user.
	user, err := p.userByIDStr(mu.UserID)
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
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUserManageAction,
		}
	}

	// Update the user in the database.
	err = p.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &www.ManageUserReply{}, nil
}

// initUserEmailsCache initializes the userEmails cache by iterating through
// all the users in the database and adding a email-userID mapping for them.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) initUserEmailsCache() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		p.userEmails[u.Email] = u.ID
	})
}

// setUserEmailsCache sets a email-userID mapping in the user emails cache.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) setUserEmailsCache(email string, id uuid.UUID) {
	p.Lock()
	defer p.Unlock()
	p.userEmails[email] = id
}

// userIDByEmail returns a userID given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) userIDByEmail(email string) (uuid.UUID, bool) {
	p.RLock()
	defer p.RUnlock()
	id, ok := p.userEmails[email]
	return id, ok
}

// userByEmail returns a User object given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) userByEmail(email string) (*user.User, error) {
	id, ok := p.userIDByEmail(email)
	if !ok {
		log.Debugf("userByEmail: email lookup failed for '%v'", email)
		return nil, user.ErrUserNotFound
	}
	return p.db.UserGetById(id)
}

// userByIDStr converts the provided userIDStr to a uuid and returns the
// corresponding user, if one it exists.
func (p *LegacyPoliteiawww) userByIDStr(userIDStr string) (*user.User, error) {
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUUID,
		}
	}

	usr, err := p.db.UserGetById(userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return nil, err
	}

	return usr, nil
}

// emailUserEmailVerify sends a new user verification email to the provided
// email address. This function is not rate limited by the smtp client because
// the user is only created/updated when this function is successfully executed
// and an email with the verification token is sent to the user. This email is
// also already limited by the verification token expiry hours policy.
func (p *LegacyPoliteiawww) emailUserEmailVerify(email, token, username string) error {
	link, err := p.createEmailLink(www.RouteVerifyNewUser, email,
		token, username)
	if err != nil {
		return err
	}

	tplData := userEmailVerify{
		Username: username,
		Link:     link,
	}

	subject := "Verify Your Email"
	body, err := createBody(userEmailVerifyTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, []string{email})
}

// emailUserKeyUpdate emails the link with the verification token used for
// setting a new key pair if the email server is set up.
func (p *LegacyPoliteiawww) emailUserKeyUpdate(username, publicKey, token string, recipient map[uuid.UUID]string) error {
	link, err := p.createEmailLink(www.RouteVerifyUpdateUserKey, "", token, "")
	if err != nil {
		return err
	}

	tplData := userKeyUpdate{
		PublicKey: publicKey,
		Username:  username,
		Link:      link,
	}

	subject := "Verify Your New Identity"
	body, err := createBody(userKeyUpdateTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordReset emails the link with the reset password verification
// token to the provided email address.
func (p *LegacyPoliteiawww) emailUserPasswordReset(username, token string, recipient map[uuid.UUID]string) error {
	// Setup URL
	u, err := url.Parse(p.cfg.WebServerAddress + www.RouteResetPassword)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("verificationtoken", token)
	q.Set("username", username)
	u.RawQuery = q.Encode()

	// Setup email
	subject := "Reset Your Password"
	tplData := userPasswordReset{
		Link: u.String(),
	}
	body, err := createBody(userPasswordResetTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserAccountLocked notifies the user its account has been locked and
// emails the link with the reset password verification token if the email
// server is set up.
func (p *LegacyPoliteiawww) emailUserAccountLocked(username string, recipient map[uuid.UUID]string) error {
	var email string
	for _, e := range recipient {
		email = e
	}
	link, err := p.createEmailLink(ResetPasswordGuiRoute,
		email, "", "")
	if err != nil {
		return err
	}

	tplData := userAccountLocked{
		Link:     link,
		Username: username,
	}

	subject := "Locked Account - Reset Your Password"
	body, err := createBody(userAccountLockedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordChanged notifies the user that his password was changed,
// and verifies if he was the author of this action, for security purposes.
func (p *LegacyPoliteiawww) emailUserPasswordChanged(username string, recipient map[uuid.UUID]string) error {
	tplData := userPasswordChanged{
		Username: username,
	}

	subject := "Password Changed - Security Notification"
	body, err := createBody(userPasswordChangedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (p *LegacyPoliteiawww) hashPassword(password string) ([]byte, error) {
	if p.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
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

// validatePubKey verifies that the provided public key is a valid ed25519
// public key.
func validatePubKey(publicKey string) error {
	pk, err := hex.DecodeString(publicKey)
	if err != nil {
		log.Debugf("validatePubKey: decode hex string "+
			"failed for '%v': %v", publicKey, err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	var emptyPK [identity.PublicKeySize]byte
	switch {
	case len(pk) != len(emptyPK):
		log.Debugf("validatePubKey: invalid size: %v",
			publicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	case bytes.Equal(pk, emptyPK[:]):
		log.Debugf("validatePubKey: key is empty: %v",
			publicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	return nil
}

// validateSignature validates an incoming signature against the specified
// public key and message. This function assumes the provided public key is
// valid.
func validateSignature(pubKey string, signature string, elements ...string) error {
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(b)
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

// userIsLocked returns whether the user's account has been locked due to
// failed login attempts.
func userIsLocked(failedLoginAttempts uint64) bool {
	return failedLoginAttempts >= LoginAttemptsToLockUser
}

// newVerificationTokenAndExpiry returns a byte slice of random data that is
// the size of a verification token and a UNIX timestamp that represents the
// expiration of the token.
func newVerificationTokenAndExpiry() ([]byte, int64, error) {
	tokenb, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}
	d := time.Duration(www.VerificationExpiryHours) * time.Hour
	expiry := time.Now().Add(d).Unix()
	return tokenb, expiry, nil
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
		Locked:                          userIsLocked(user.FailedLoginAttempts),
		Identities:                      convertWWWIdentitiesFromDatabaseIdentities(user.Identities),
		ProposalCredits:                 uint64(len(user.UnspentProposalCredits)),
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
