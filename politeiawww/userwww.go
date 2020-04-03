// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var (
	templateNewUserEmail = template.Must(
		template.New("new_user_email_template").Parse(templateNewUserEmailRaw))
	templateResetPasswordEmail = template.Must(
		template.New("reset_password_email_template").Parse(templateResetPasswordEmailRaw))
	templateUpdateUserKeyEmail = template.Must(
		template.New("update_user_key_email_template").Parse(templateUpdateUserKeyEmailRaw))
	templateUserLockedResetPassword = template.Must(
		template.New("user_locked_reset_password").Parse(templateUserLockedResetPasswordRaw))
	templateUserPasswordChanged = template.Must(
		template.New("user_changed_password").Parse(templateUserPasswordChangedRaw))
	templateInviteNewUserEmail = template.Must(
		template.New("invite_new_user_email_template").Parse(templateInviteNewUserEmailRaw))
	templateApproveDCCUserEmail = template.Must(
		template.New("invite_approved_dcc_user").Parse(templateApproveDCCUserEmailRaw))
)

// handleNewUser handles the incoming new user command. It verifies that the new user
// doesn't already exist, and then creates a new user in the db and generates a random
// code used for verification. The code is intended to be sent to the specified email.
func (p *politeiawww) handleNewUser(w http.ResponseWriter, r *http.Request) {
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

// handleVerifyNewUser handles the incoming new user verify command. It verifies
// that the user with the provided email has a verification token that matches
// the provided token and that the verification token has not yet expired.
func (p *politeiawww) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
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
func (p *politeiawww) handleResendVerification(w http.ResponseWriter, r *http.Request) {
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
		usrErr, ok := err.(www.UserError)
		if ok {
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
func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
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
	err = p.initSession(w, r, reply.UserID)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogin: initSession: %v", err)
		return
	}

	// Set session max age
	reply.SessionMaxAge = sessionMaxAge

	// Reply with the user information.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLogout logs the user out.
func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLogout")

	_, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleLogout: getSessionUser", www.UserError{
			ErrorCode: www.ErrorStatusNotLoggedIn,
		})
		return
	}

	err = p.removeSession(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogout: removeSession %v", err)
		return
	}

	// Reply with the user information.
	var reply www.LogoutReply
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleResetPassword handles the reset password command.
func (p *politeiawww) handleResetPassword(w http.ResponseWriter, r *http.Request) {
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
func (p *politeiawww) handleVerifyResetPassword(w http.ResponseWriter, r *http.Request) {
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
func (p *politeiawww) handleUserDetails(w http.ResponseWriter, r *http.Request) {
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
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
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

// handleSecret is a mock handler to test privileged routes.
func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSecret")

	fmt.Fprintf(w, "secret sauce")
}

// handleMe returns logged in user information.
func (p *politeiawww) handleMe(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleMe")

	user, err := p.getSessionUser(w, r)
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
	reply.SessionMaxAge = sessionMaxAge

	util.RespondWithJSON(w, http.StatusOK, *reply)
}

// handleUpdateUserKey handles the incoming update user key command. It generates
// a random code used for verification. The code is intended to be sent to the
// email of the logged in user.
func (p *politeiawww) handleUpdateUserKey(w http.ResponseWriter, r *http.Request) {
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

	user, err := p.getSessionUser(w, r)
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

// handleVerifyUpdateUserKey handles the incoming update user key verify command. It verifies
// that the user with the provided email has a verification token that matches
// the provided token and that the verification token has not yet expired.
func (p *politeiawww) handleVerifyUpdateUserKey(w http.ResponseWriter, r *http.Request) {
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

	user, err := p.getSessionUser(w, r)
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
func (p *politeiawww) handleChangeUsername(w http.ResponseWriter, r *http.Request) {
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

	user, err := p.getSessionUser(w, r)
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
func (p *politeiawww) handleChangePassword(w http.ResponseWriter, r *http.Request) {
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

	session, err := p.getSession(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: getSession %v", err)
		return
	}
	user, err := p.getSessionUser(w, r)
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

// handleVerifyUserPayment checks whether the provided transaction
// is on the blockchain and meets the requirements to consider the user
// registration fee as paid.
func (p *politeiawww) handleVerifyUserPayment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyUserPayment")

	// Get the verify user payment tx command.
	var vupt www.VerifyUserPayment
	err := util.ParseGetParams(r, &vupt)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyUserPayment: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPayment: getSessionUser %v", err)
		return
	}

	vuptr, err := p.processVerifyUserPayment(user, vupt)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPayment: processVerifyUserPayment %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vuptr)
}

// handleEditUser handles editing a user's preferences.
func (p *politeiawww) handleEditUser(w http.ResponseWriter, r *http.Request) {
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

	adminUser, err := p.getSessionUser(w, r)
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

// handleUsers handles fetching a list of users.
func (p *politeiawww) handleUsers(w http.ResponseWriter, r *http.Request) {
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
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
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

// handleCMSUsers handles fetching a list of cms users.
func (p *politeiawww) handleCMSUsers(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCMSUsers")

	var cu cms.CMSUsers
	err := util.ParseGetParams(r, &cu)
	if err != nil {
		RespondWithError(w, r, 0, "handleCMSUsers: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	cur, err := p.processCMSUsers(&cu)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCMSUsers: processCMSUsers %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cur)
}

// handleUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (p *politeiawww) handleUserPaymentsRescan(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserPaymentsRescan")

	var upr www.UserPaymentsRescan
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&upr); err != nil {
		RespondWithError(w, r, 0, "handleUserPaymentsRescan: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processUserPaymentsRescan(upr)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserPaymentsRescan: processUserPaymentsRescan:  %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleManageUser handles editing a user's details.
func (p *politeiawww) handleManageUser(w http.ResponseWriter, r *http.Request) {
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

	adminUser, err := p.getSessionUser(w, r)
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

// handleUserCommentsLikes returns the user votes on comments of a given proposal.
func (p *politeiawww) handleUserCommentsLikes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserCommentsLikes")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserCommentsLikes: getSessionUser %v", err)
		return
	}

	uclr, err := p.processUserCommentsLikes(user, token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserCommentsLikes: processUserCommentsLikes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, uclr)
}

// handleUserProposalCredits returns the spent and unspent proposal credits for
// the logged in user.
func (p *politeiawww) handleUserProposalCredits(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposalCredits")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: getSessionUser %v", err)
		return
	}

	reply, err := processUserProposalCredits(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: processUserProposalCredits  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleRegisterUser handles the completion of registration by invited users of
// the Contractor Management System.
func (p *politeiawww) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRegisterUser")

	// Get the new user command.
	var u cms.RegisterUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processRegisterUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: ProcessRegisterUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// setUserWWWRoutes setsup the user routes.
func (p *politeiawww) setUserWWWRoutes() {
	// Public routes
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteNewUser, p.handleNewUser,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyNewUser, p.handleVerifyNewUser,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteResendVerification, p.handleResendVerification,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogin, p.handleLogin,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogout, p.handleLogout,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteResetPassword, p.handleResetPassword,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyResetPassword, p.handleVerifyResetPassword,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserDetails, p.handleUserDetails,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUsers, p.handleUsers,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSecret, p.handleSecret,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserMe, p.handleMe,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteUpdateUserKey, p.handleUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUpdateUserKey, p.handleVerifyUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangeUsername, p.handleChangeUsername,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangePassword, p.handleChangePassword,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUserPayment, p.handleVerifyUserPayment,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteEditUser, p.handleEditUser,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserCommentsLikes, p.handleUserCommentsLikes,
		permissionLogin) // XXX comments need to become a setting
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserProposalCredits, p.handleUserProposalCredits,
		permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodPut, www.PoliteiaWWWAPIRoute,
		www.RouteUserPaymentsRescan, p.handleUserPaymentsRescan,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteManageUser, p.handleManageUser,
		permissionAdmin)
}

// setCMSUserWWWRoutes setsup the user routes for cms mode
func (p *politeiawww) setCMSUserWWWRoutes() {
	// Public routes
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogin, p.handleLogin,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogout, p.handleLogout,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteResetPassword, p.handleResetPassword,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyResetPassword, p.handleVerifyResetPassword,
		permissionPublic)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteRegisterUser, p.handleRegisterUser,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSecret, p.handleSecret,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserMe, p.handleMe,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteUpdateUserKey, p.handleUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUpdateUserKey, p.handleVerifyUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangeUsername, p.handleChangeUsername,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangePassword, p.handleChangePassword,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		www.RouteUserDetails, p.handleCMSUserDetails,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		www.RouteEditUser, p.handleEditCMSUser,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUsers, p.handleUsers,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteCMSUsers, p.handleCMSUsers,
		permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUsers, p.handleUsers,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteManageCMSUser, p.handleManageCMSUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteManageUser, p.handleManageUser,
		permissionAdmin)
}
