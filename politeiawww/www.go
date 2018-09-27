package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/tls"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionLogin
	permissionAdmin

	csrfKeyLength = 32
	sessionMaxAge = 86400 //One day
)

// politeiawww application context.
type politeiawww struct {
	cfg    *config
	router *mux.Router

	store *sessions.FilesystemStore

	backend *backend
}

type newUserEmailTemplateData struct {
	Link  string
	Email string
}
type updateUserKeyEmailTemplateData struct {
	Link      string
	PublicKey string
	Email     string
}
type resetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

// getSession returns the active cookie session.
func (p *politeiawww) getSession(r *http.Request) (*sessions.Session, error) {
	return p.store.Get(r, v1.CookieSession)
}

// getSessionEmail returns the email address of the currently logged in user
// from the session store.
func (p *politeiawww) getSessionEmail(r *http.Request) (string, error) {
	session, err := p.getSession(r)
	if err != nil {
		return "", err
	}

	email, ok := session.Values["email"].(string)
	if !ok {
		// No email in session so return "" to indicate that.
		return "", nil
	}

	return email, nil
}

// getSessionUser retrieves the current session user from the database.
func (p *politeiawww) getSessionUser(r *http.Request) (*database.User, error) {
	log.Tracef("getSessionUser")
	email, err := p.getSessionEmail(r)
	if err != nil {
		return nil, err
	}

	return p.backend.db.UserGet(email)
}

// setSessionUser sets the "email" session key to the provided value.
func (p *politeiawww) setSessionUser(w http.ResponseWriter, r *http.Request, email string) error {
	log.Tracef("setSessionUser: %v %v", email, v1.CookieSession)
	session, err := p.getSession(r)
	if err != nil {
		return err
	}

	session.Values["email"] = email
	return session.Save(r, w)
}

// removeSession deletes the session from the filesystem.
func (p *politeiawww) removeSession(w http.ResponseWriter, r *http.Request) error {
	log.Tracef("removeSession: %v", v1.CookieSession)
	session, err := p.getSession(r)
	if err != nil {
		return err
	}

	// Check for invalid session.
	if session.ID == "" {
		return nil
	}

	// Saving the session with a negative MaxAge will cause it to be deleted
	// from the filesystem.
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

// isAdmin returns true if the current session has admin privileges.
func (p *politeiawww) isAdmin(r *http.Request) (bool, error) {
	user, err := p.getSessionUser(r)
	if err != nil {
		return false, err
	}

	return user.Admin, nil
}

// Fetch remote identity
func (p *politeiawww) getIdentity() error {
	id, err := util.RemoteIdentity(false, p.cfg.RPCHost, p.cfg.RPCCert)
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("Key        : %x", id.Key)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	if p.cfg.Interactive != allowInteractive {
		// Ask user if we like this identity
		log.Infof("Save to %v or ctrl-c to abort", p.cfg.RPCIdentityFile)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err = scanner.Err(); err != nil {
			return err
		}
	} else {
		log.Infof("Saving identity to %v", p.cfg.RPCIdentityFile)
	}

	// Save identity
	err = os.MkdirAll(filepath.Dir(p.cfg.RPCIdentityFile), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(p.cfg.RPCIdentityFile)
	if err != nil {
		return err
	}
	log.Infof("Identity saved to: %v", p.cfg.RPCIdentityFile)

	return nil
}

// RespondWithError returns an HTTP error status to the client. If it's a user
// error, it returns a 4xx HTTP status and the specific user error code. If it's
// an internal server error, it returns 500 and an error code which is also
// outputted to the logs so that it can be correlated later if the user
// files a complaint.
func RespondWithError(w http.ResponseWriter, r *http.Request, userHttpCode int, format string, args ...interface{}) {
	// XXX this function needs to get an error in and a format + args
	// instead of what it is doing now.
	// So inError error, format string, args ...interface{}
	// if err == nil -> internal error using format + args
	// if err != nil -> if defined error -> return defined error + log.Errorf format+args
	// if err != nil -> if !defined error -> return + log.Errorf format+args
	if userErr, ok := args[0].(v1.UserError); ok {
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Errorf("RespondWithError: %v %v",
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode])
		} else {
			log.Errorf("RespondWithError: %v %v: %v",
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode],
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHttpCode,
			v1.ErrorReply{
				ErrorCode:    int64(userErr.ErrorCode),
				ErrorContext: userErr.ErrorContext,
			})
		return
	}

	if pdError, ok := args[0].(v1.PDError); ok {
		pdErrorCode := convertErrorStatusFromPD(pdError.ErrorReply.ErrorCode)
		if pdErrorCode == v1.ErrorStatusInvalid {
			errorCode := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error "+
				"code from politeiad: %v", remoteAddr(r),
				r.Method, r.URL, r.Proto, errorCode,
				pdError.ErrorReply.ErrorCode)
			util.RespondWithJSON(w, http.StatusInternalServerError,
				v1.ErrorReply{
					ErrorCode: errorCode,
				})
			return
		}

		util.RespondWithJSON(w, pdError.HTTPCode,
			v1.ErrorReply{
				ErrorCode:    int64(pdErrorCode),
				ErrorContext: pdError.ErrorReply.ErrorContext,
			})
		return
	}

	errorCode := time.Now().Unix()
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", remoteAddr(r),
		r.Method, r.URL, r.Proto, errorCode)
	log.Errorf(ec+format, args...)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		v1.ErrorReply{
			ErrorCode: errorCode,
		})
}

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	versionReply, err := json.Marshal(v1.VersionReply{
		Version: v1.PoliteiaWWWAPIVersion,
		Route:   v1.PoliteiaWWWAPIRoute,
		PubKey:  hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet: p.cfg.TestNet,
	})
	if err != nil {
		RespondWithError(w, r, 0, "handleVersion: Marshal %v", err)
		return
	}

	// Check if there's an active AND invalid session.
	session, err := p.getSession(r)
	if err != nil && session != nil {
		// Create and save a new session for the user.
		session := sessions.NewSession(p.store, v1.CookieSession)
		opts := *p.store.Options
		session.Options = &opts
		session.IsNew = true
		err = session.Save(r, w)
		if err != nil {
			RespondWithError(w, r, 0, "handleVersion: session.Save %v", err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Strict-Transport-Security",
		"max-age=63072000; includeSubDomains")
	w.Header().Set(v1.CsrfToken, csrf.Token(r))
	w.WriteHeader(http.StatusOK)
	w.Write(versionReply)
}

// handleNewUser handles the incoming new user command. It verifies that the new user
// doesn't already exist, and then creates a new user in the db and generates a random
// code used for verification. The code is intended to be sent to the specified email.
func (p *politeiawww) handleNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewUser")

	// Get the new user command.
	var u v1.NewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleNewUser: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.backend.ProcessNewUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleNewUser: ProcessNewUser %v", err)
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
	var vnu v1.VerifyNewUser
	err := util.ParseGetParams(r, &vnu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyNewUser: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	_, err = p.backend.ProcessVerifyNewUser(vnu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyNewUser: "+
			"ProcessVerifyNewUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.VerifyNewUserReply{})
}

// handleResendVerification sends another verification email for new user
// signup, if there is an existing verification token and it is expired.
func (p *politeiawww) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleResendVerification")

	// Get the resend verification command.
	var rv v1.ResendVerification
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rv); err != nil {
		RespondWithError(w, r, 0, "handleResendVerification: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	rvr, err := p.backend.ProcessResendVerification(&rv)
	if err != nil {
		RespondWithError(w, r, 0, "handleResendVerification: "+
			"ProcessResendVerification %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, *rvr)
}

// handleUpdateUserKey handles the incoming update user key command. It generates
// a random code used for verification. The code is intended to be sent to the
// email of the logged in user.
func (p *politeiawww) handleUpdateUserKey(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUpdateUserKey")

	// Get the update user key command.
	var u v1.UpdateUserKey
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleUpdateUserKey: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUpdateUserKey: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessUpdateUserKey(user, u)
	if err != nil {
		RespondWithError(w, r, 0, "handleUpdateUserKey: ProcessUpdateUserKey %v", err)
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
	var vuu v1.VerifyUpdateUserKey
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vuu); err != nil {
		RespondWithError(w, r, 0, "handleVerifyUpdateUserKey: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUpdateUserKey: getSessionUser %v", err)
		return
	}

	_, err = p.backend.ProcessVerifyUpdateUserKey(user, vuu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyUpdateUserKey: "+
			"ProcessVerifyUpdateUserKey %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.VerifyUpdateUserKeyReply{})
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLogin")

	// Get the login command.
	var l v1.Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&l); err != nil {
		RespondWithError(w, r, 0, "handleLogin: failed to decode: %v", err)
		return
	}

	reply, err := p.backend.ProcessLogin(l)
	if err != nil {
		RespondWithError(w, r, http.StatusUnauthorized,
			"handleLogin: ProcessLogin %v", err)
		return
	}

	// Mark user as logged in if there's no error.
	err = p.setSessionUser(w, r, l.Email)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogin: setSessionUser %v", err)
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

	_, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0, "handleLogout: getSessionUser", v1.UserError{
			ErrorCode: v1.ErrorStatusNotLoggedIn,
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
	var reply v1.LogoutReply
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSecret is a mock handler to test privileged routes.
func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSecret")

	fmt.Fprintf(w, "secret sauce")
}

// handleMe returns logged in user information.
func (p *politeiawww) handleMe(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleMe")

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.CreateLoginReply(user, user.LastLoginTime)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: CreateLoginReply %v", err)
		return
	}

	// Set session max age
	reply.SessionMaxAge = sessionMaxAge

	util.RespondWithJSON(w, http.StatusOK, *reply)
}

func (p *politeiawww) handleChangeUsername(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleChangeUsername")

	// Get the change username command.
	var cu v1.ChangeUsername
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cu); err != nil {
		RespondWithError(w, r, 0, "handleChangeUsername: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangeUsername: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessChangeUsername(user.Email, cu)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangeUsername: ProcessChangeUsername %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleChangePassword")

	// Get the change password command.
	var cp v1.ChangePassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cp); err != nil {
		RespondWithError(w, r, 0, "handleChangePassword: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessChangePassword(user.Email, cp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: ProcessChangePassword %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	log.Trace("handleResetPassword")

	// Get the reset password command.
	var rp v1.ResetPassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rp); err != nil {
		RespondWithError(w, r, 0, "handleResetPassword: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	rpr, err := p.backend.ProcessResetPassword(rp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleResetPassword: ProcessResetPassword %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, rpr)
}

// handleProposalPaywallDetails returns paywall details that allows the user to
// purchase proposal credits.
func (p *politeiawww) handleProposalPaywallDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalPaywallDetails")

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessProposalPaywallDetails(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: ProcessProposalPaywallDetails  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewProposal handles the incoming new proposal command.
func (p *politeiawww) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	log.Tracef("handleNewProposal")
	var np v1.NewProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		RespondWithError(w, r, 0, "handleNewProposal: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessNewProposal(np, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: ProcessNewProposal %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSetProposalStatus handles the incoming set proposal status command.
// It's used for either publishing or censoring a proposal.
func (p *politeiawww) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	// Get the proposal status command.
	log.Tracef("handleSetProposalStatus")
	var sps v1.SetProposalStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sps); err != nil {
		RespondWithError(w, r, 0, "handleSetProposalStatus: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: getSessionUser %v", err)
		return
	}

	// Set status
	reply, err := p.backend.ProcessSetProposalStatus(sps, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: ProcessSetProposalStatus %v", err)
		return
	}

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleProposalDetails handles the incoming proposal details command. It fetches
// the complete details for an existing proposal.
func (p *politeiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
	// Add the path param to the struct.
	log.Tracef("handleProposalDetails")
	pathParams := mux.Vars(r)
	var pd v1.ProposalsDetails
	pd.Token = pathParams["token"]

	user, err := p.getSessionUser(r)
	if err != nil {
		if err != database.ErrUserNotFound {
			RespondWithError(w, r, 0,
				"handleProposalDetails: getSessionUser %v", err)
			return
		}
	}
	reply, err := p.backend.ProcessProposalDetails(pd, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: ProcessProposalDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleUsernamesById(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUsernamesById")

	// Get the UsernamesById command.
	var ubi v1.UsernamesById
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ubi); err != nil {
		RespondWithError(w, r, 0, "handleUsernamesById: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	// Reply with the usernames.
	util.RespondWithJSON(w, http.StatusOK, p.backend.ProcessUsernamesById(ubi))
}

func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	// Get the policy command.
	log.Tracef("handlePolicy")
	var policy v1.Policy
	reply := p.backend.ProcessPolicy(policy)
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleAllVetted replies with the list of vetted proposals.
func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllVetted")

	// Get the all vetted command.
	var v v1.GetAllVetted
	err := util.ParseGetParams(r, &v)
	if err != nil {
		RespondWithError(w, r, 0, "handleAllVetted: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	vr := p.backend.ProcessAllVetted(v)
	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleAllUnvetted replies with the list of unvetted proposals.
func (p *politeiawww) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllUnvetted")

	// Get the all unvetted command.
	var u v1.GetAllUnvetted
	err := util.ParseGetParams(r, &u)
	if err != nil {
		RespondWithError(w, r, 0, "handleAllUnvetted: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	ur := p.backend.ProcessAllUnvetted(u)
	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleNewComment handles incomming comments.
func (p *politeiawww) handleNewComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewComment")

	var sc v1.NewComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0, "handleNewComment: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: getSessionUser %v", err)
		return
	}

	cr, err := p.backend.ProcessComment(sc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: ProcessComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleLikeComment handles up or down voting of commentd.
func (p *politeiawww) handleLikeComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLikeComment")

	var lc v1.LikeComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&lc); err != nil {
		RespondWithError(w, r, 0, "handleLikeComment: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLikeComment: getSessionUser %v", err)
		return
	}

	cr, err := p.backend.ProcessLikeComment(lc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLikeComment: ProcessLikeComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleCensorComment handles the censoring of a comment by an admin.
func (p *politeiawww) handleCensorComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCensorComment")

	var cc v1.CensorComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cc); err != nil {
		RespondWithError(w, r, 0, "handleCensorComment: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCensorComment: getSessionUser %v", err)
		return
	}

	cr, err := p.backend.ProcessCensorComment(cc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCensorComment: ProcessCensorComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleCommentsGet handles batched comments get.
func (p *politeiawww) handleCommentsGet(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentsGet")

	pathParams := mux.Vars(r)
	gcr, err := p.backend.ProcessCommentGet(pathParams["token"])
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: ProcessCommentGet %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gcr)
}

// handleVerifyUserPayment checks whether the provided transaction
// is on the blockchain and meets the requirements to consider the user
// registration fee as paid.
func (p *politeiawww) handleVerifyUserPayment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyUserPayment")

	// Get the verify user payment tx command.
	var vupt v1.VerifyUserPayment
	err := util.ParseGetParams(r, &vupt)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyUserPayment: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPayment: getSessionUser %v", err)
		return
	}

	vuptr, err := p.backend.ProcessVerifyUserPayment(user, vupt)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPayment: ProcessVerifyUserPayment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vuptr)
}

// handleUserProposalCredits returns the spent and unspent proposal credits for
// the logged in user.
func (p *politeiawww) handleUserProposalCredits(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposalCredits")

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalPayments: getSessionUser %v", err)
		return
	}

	reply, err := p.backend.ProcessUserProposalCredits(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: ProcessUserProposalCredits  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserProposals returns the proposals for the given user.
func (p *politeiawww) handleUserProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposals")

	// Get the user proposals command.
	var up v1.UserProposals
	err := util.ParseGetParams(r, &up)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	userId, err := uuid.Parse(up.UserId)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseUint",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		// since having a logged in user isn't required, simply log the error
		log.Infof("handleUserDetails: could not get session user %v", err)
	}

	upr, err := p.backend.ProcessUserProposals(
		&up,
		user != nil && user.ID == userId,
		user != nil && user.Admin)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposals: ProcessUserProposals %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, upr)
}

// handleActiveVote returns all active proposals that have an active vote.
func (p *politeiawww) handleActiveVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleActiveVote")

	avr, err := p.backend.ProcessActiveVote()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleActiveVote: ProcessActivateVote %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleCastVotes records the user votes in politeiad.
func (p *politeiawww) handleCastVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastVotes")

	var cv v1.Ballot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		RespondWithError(w, r, 0, "handleCastVotes: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	avr, err := p.backend.ProcessCastVotes(&cv)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVotes: ProcessCastVotes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleVoteResults returns a proposal + all voting action.
func (p *politeiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	vrr, err := p.backend.ProcessVoteResults(token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteResults: ProcessVoteResults %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

// handleAuthorizeVote handles authorizing a proposal vote.
func (p *politeiawww) handleAuthorizeVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAuthorizeVote")
	var av v1.AuthorizeVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&av); err != nil {
		RespondWithError(w, r, 0, "handleAuthorizeVote: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}
	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: getSessionUser %v", err)
		return
	}
	avr, err := p.backend.ProcessAuthorizeVote(av, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: ProcessAuthorizeVote %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleStartVote handles starting a vote.
func (p *politeiawww) handleStartVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleStartVote")

	var sv v1.StartVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sv); err != nil {
		RespondWithError(w, r, 0, "handleStartVote: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: getSessionUser %v", err)
		return
	}

	// Sanity
	if !user.Admin {
		RespondWithError(w, r, 0,
			"handleStartVote: admin %v", user.Admin)
		return
	}

	svr, err := p.backend.ProcessStartVote(sv, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: ProcessStartVote %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, svr)
}

// handleUserDetails handles fetching user details by user id.
func (p *politeiawww) handleUserDetails(w http.ResponseWriter, r *http.Request) {
	// Add the path param to the struct.
	log.Tracef("handleUserDetails")
	pathParams := mux.Vars(r)
	var ud v1.UserDetails
	ud.UserID = pathParams["userid"]

	userID, err := uuid.Parse(ud.UserID)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseUint",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		// since having a logged in user isn't required, simply log the error
		log.Infof("handleUserDetails: could not get session user %v", err)
	}

	udr, err := p.backend.ProcessUserDetails(&ud,
		user != nil && user.ID == userID,
		user != nil && user.Admin,
	)

	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserDetails: ProcessUserDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, udr)
}

// handleEditUser handles editing a user's details.
func (p *politeiawww) handleEditUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleEditUser")

	var eu v1.EditUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&eu); err != nil {
		RespondWithError(w, r, 0, "handleEditUser: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	adminUser, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0, "handleEditUser: getSessionUser %v", err)
		return
	}

	eur, err := p.backend.ProcessEditUser(&eu, adminUser)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditUser: ProcessEditUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, eur)
}

// handleGetAllVoteStatus returns the voting status of all public proposals.
func (p *politeiawww) handleGetAllVoteStatus(w http.ResponseWriter, r *http.Request) {
	gasvr, err := p.backend.ProcessGetAllVoteStatus()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalsVotingStatus: ProcessProposalsVotingStatus %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, gasvr)
}

// handleVoteStatus returns the vote status for a given proposal.
func (p *politeiawww) handleVoteStatus(w http.ResponseWriter, r *http.Request) {
	pathParams := mux.Vars(r)
	vsr, err := p.backend.ProcessVoteStatus(pathParams["token"])
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: ProcessCommentGet %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, vsr)
}

// handleUserCommentsVotes returns the user votes on comments of a given proposal.
func (p *politeiawww) handleUserCommentsVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserCommentsVotes")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserCommentsVotes: getSessionUser %v", err)
		return
	}

	ucvr, err := p.backend.ProcessUserCommentsVotes(user, token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserCommentsVotes: processUserCommentsVotes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ucvr)
}

// handleEditProposal attempts to edit a proposal
func (p *politeiawww) handleEditProposal(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleEditProposal")

	var ep v1.EditProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ep); err != nil {
		RespondWithError(w, r, 0, "handleEditProposal: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: getSessionUser %v", err)
		return
	}

	epr, err := p.backend.ProcessEditProposal(user, ep)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: processEditProposal %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, epr)
}

// handleProposalsStats returns the counting of proposals aggrouped by each proposal status
func (p *politeiawww) handleProposalsStats(w http.ResponseWriter, r *http.Request) {
	psr := p.backend.ProcessProposalsStats()
	util.RespondWithJSON(w, http.StatusOK, psr)
}

// handleNotFound is a generic handler for an invalid route.
func (p *politeiawww) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// Log incoming connection
	log.Debugf("Invalid route: %v %v %v %v", remoteAddr(r), r.Method, r.URL,
		r.Proto)

	// Trace incoming request
	log.Tracef("%v", newLogClosure(func() string {
		trace, err := httputil.DumpRequest(r, true)
		if err != nil {
			trace = []byte(fmt.Sprintf("logging: "+
				"DumpRequest %v", err))
		}
		return string(trace)
	}))

	util.RespondWithJSON(w, http.StatusNotFound, v1.ErrorReply{})
}

// addRoute sets up a handler for a specific method+route.
func (p *politeiawww) addRoute(method string, route string, handler http.HandlerFunc, perm permission, shouldLoadInventory bool) {
	fullRoute := v1.PoliteiaWWWAPIRoute + route

	if shouldLoadInventory {
		handler = p.loadInventory(handler)
	}
	switch perm {
	case permissionAdmin:
		handler = logging(p.isLoggedInAsAdmin(handler))
	case permissionLogin:
		handler = logging(p.isLoggedIn(handler))
	default:
		handler = logging(handler)
	}

	// All handlers need to close the body
	handler = closeBody(handler)

	p.router.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	if loadedCfg.PaywallAmount != 0 && loadedCfg.PaywallXpub != "" {
		paywallAmountInDcr := float64(loadedCfg.PaywallAmount) / 1e8
		log.Infof("Paywall : %v DCR", paywallAmountInDcr)
	} else if loadedCfg.PaywallAmount == 0 && loadedCfg.PaywallXpub == "" {
		log.Infof("Paywall : DISABLED")
	} else {
		return fmt.Errorf("Paywall settings invalid, both an amount " +
			"and public key MUST be set")
	}

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Setup application context.
	p := &politeiawww{
		cfg: loadedCfg,
	}

	// Check if this command is being run to fetch the identity.
	if p.cfg.FetchIdentity {
		return p.getIdentity()
	}

	p.backend, err = NewBackend(p.cfg)
	if err != nil {
		return err
	}
	p.backend.params = activeNetParams.Params

	// Try to load inventory but do not fail.
	log.Infof("Attempting to load proposal inventory")
	err = p.backend.LoadInventory()
	if err != nil {
		log.Errorf("LoadInventory: %v", err)
	}

	// Load or create new CSRF key
	log.Infof("Load CSRF key")
	csrfKeyFilename := filepath.Join(p.cfg.DataDir, "csrf.key")
	fCSRF, err := os.Open(csrfKeyFilename)
	if err != nil {
		if os.IsNotExist(err) {
			key, err := util.Random(csrfKeyLength)
			if err != nil {
				return err
			}

			// Persist key
			fCSRF, err = os.OpenFile(csrfKeyFilename,
				os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			_, err = fCSRF.Write(key)
			if err != nil {
				return err
			}
			_, err = fCSRF.Seek(0, 0)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	csrfKey := make([]byte, csrfKeyLength)
	r, err := fCSRF.Read(csrfKey)
	if err != nil {
		return err
	}
	if r != csrfKeyLength {
		return fmt.Errorf("CSRF key corrupt")
	}
	fCSRF.Close()

	csrfHandle := csrf.Protect(csrfKey, csrf.Path("/"))

	p.router = mux.NewRouter()

	// Static content.
	// XXX disable static for now.  This code is broken and it needs to
	// point to a sane directory.  If a directory is not set it SHALL be
	// disabled.
	//p.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/",
	//	http.FileServer(http.Dir("."))))

	// Public routes.
	p.router.HandleFunc("/", closeBody(logging(p.handleVersion))).Methods(http.MethodGet)
	p.router.NotFoundHandler = closeBody(p.handleNotFound)
	p.addRoute(http.MethodGet, v1.RouteVersion, p.handleVersion,
		permissionPublic, false)
	p.addRoute(http.MethodPost, v1.RouteNewUser, p.handleNewUser,
		permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteVerifyNewUser,
		p.handleVerifyNewUser, permissionPublic, false)
	p.addRoute(http.MethodPost, v1.RouteResendVerification,
		p.handleResendVerification, permissionPublic, false)
	p.addRoute(http.MethodPost, v1.RouteLogin, p.handleLogin,
		permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteLogout, p.handleLogout,
		permissionPublic, false)
	p.addRoute(http.MethodPost, v1.RouteLogout, p.handleLogout,
		permissionPublic, false)
	p.addRoute(http.MethodPost, v1.RouteResetPassword,
		p.handleResetPassword, permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteAllVetted, p.handleAllVetted,
		permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteProposalDetails,
		p.handleProposalDetails, permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy,
		permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteUserProposals, p.handleUserProposals,
		permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteActiveVote, p.handleActiveVote,
		permissionPublic, true)
	p.addRoute(http.MethodPost, v1.RouteCastVotes, p.handleCastVotes,
		permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteVoteResults,
		p.handleVoteResults, permissionPublic, true)
	p.addRoute(http.MethodPost, v1.RouteUsernamesById, p.handleUsernamesById,
		permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteAllVoteStatus,
		p.handleGetAllVoteStatus, permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteVoteStatus,
		p.handleVoteStatus, permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RouteUserDetails,
		p.handleUserDetails, permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RoutePropsStats,
		p.handleProposalsStats, permissionPublic, true)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret,
		permissionLogin, false)
	p.addRoute(http.MethodGet, v1.RouteProposalPaywallDetails,
		p.handleProposalPaywallDetails, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteNewProposal, p.handleNewProposal,
		permissionLogin, true)
	p.addRoute(http.MethodGet, v1.RouteUserMe, p.handleMe, permissionLogin,
		false)
	p.addRoute(http.MethodPost, v1.RouteUpdateUserKey,
		p.handleUpdateUserKey, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteVerifyUpdateUserKey,
		p.handleVerifyUpdateUserKey, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteChangeUsername,
		p.handleChangeUsername, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteChangePassword,
		p.handleChangePassword, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteNewComment,
		p.handleNewComment, permissionLogin, true)
	p.addRoute(http.MethodPost, v1.RouteLikeComment,
		p.handleLikeComment, permissionLogin, true)
	p.addRoute(http.MethodGet, v1.RouteVerifyUserPayment,
		p.handleVerifyUserPayment, permissionLogin, false)
	p.addRoute(http.MethodGet, v1.RouteUserCommentsVotes,
		p.handleUserCommentsVotes, permissionLogin, true)
	p.addRoute(http.MethodGet, v1.RouteUserProposalCredits,
		p.handleUserProposalCredits, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteEditProposal,
		p.handleEditProposal, permissionLogin, true)
	p.addRoute(http.MethodPost, v1.RouteAuthorizeVote,
		p.handleAuthorizeVote, permissionLogin, false)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted,
		permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus,
		p.handleSetProposalStatus, permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteStartVote,
		p.handleStartVote, permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteEditUser,
		p.handleEditUser, permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteCensorComment,
		p.handleCensorComment, permissionAdmin, true)

	// Persist session cookies.
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(p.cfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(p.cfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return err
		}
		log.Infof("Cookie key generated.")
	}
	sessionsDir := filepath.Join(p.cfg.DataDir, "sessions")
	err = os.MkdirAll(sessionsDir, 0700)
	if err != nil {
		return err
	}
	p.store = sessions.NewFilesystemStore(sessionsDir, cookieKey)
	p.store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAge,
		Secure:   true,
		HttpOnly: true,
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			cfg := &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256, // BLAME CHROME, NOT ME!
					tls.CurveP521,
					tls.X25519},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				},
			}
			srv := &http.Server{
				Handler:   csrfHandle(p.router),
				Addr:      listen,
				TLSConfig: cfg,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler)),
			}

			log.Infof("Listen: %v", listen)
			listenC <- srv.ListenAndServeTLS(loadedCfg.HTTPSCert,
				loadedCfg.HTTPSKey)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:

	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
