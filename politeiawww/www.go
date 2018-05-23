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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
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

// getSessionEmail returns the email address of the currently logged in user
// from the session store.
func (p *politeiawww) getSessionEmail(r *http.Request) (string, error) {
	session, err := p.store.Get(r, v1.CookieSession)
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
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		return err
	}

	session.Values["email"] = email
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
	log.Errorf("Stacktrace: %s", debug.Stack())
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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Strict-Transport-Security",
		"max-age=63072000; includeSubDomains")
	if !p.cfg.Proxy {
		w.Header().Set(v1.CsrfToken, csrf.Token(r))
	}
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

	// Reply with the user information.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLogout logs the user out.  A login will be required to resume sending
// commands,
func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLogout")

	err := p.setSessionUser(w, r, "")
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogout: setSessionUser %v", err)
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

	reply := p.backend.CreateLoginReply(user)
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
		RespondWithError(w, r, 0, "handleNewComment: unmarshal", v1.UserError{
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

// handleVerifyUserPaymentTx checks whether the provided transaction
// is on the blockchain and meets the requirements to consider the user
// registration fee as paid.
func (p *politeiawww) handleVerifyUserPaymentTx(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyUserPaymentTx")

	// Get the verify user payment tx command.
	var vupt v1.VerifyUserPaymentTx
	err := util.ParseGetParams(r, &vupt)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyUserPaymentTx: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPaymentTx: getSessionUser %v", err)
		return
	}

	vuptr, err := p.backend.ProcessVerifyUserPaymentTx(user, vupt)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPaymentTx: ProcessVerifyUserPaymentTx %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vuptr)
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

	userId, err := strconv.ParseUint(up.UserId, 10, 64)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseUint",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposals: getSessionUser %v", err)
		return
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

// handleProposalVotes returns a proposal + all voting action.
func (p *politeiawww) handleProposalVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalVotes")

	var gpv v1.ProposalVotes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&gpv); err != nil {
		RespondWithError(w, r, 0, "handleProposalVotes: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	gpvr, err := p.backend.ProcessProposalVotes(&gpv)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalVotes: ProcessProposalVotes %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gpvr)
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

	paywallAmountInDcr := float64(loadedCfg.PaywallAmount) / 1e8
	log.Infof("Paywall : %v DCR", paywallAmountInDcr)

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

	var csrfHandle func(http.Handler) http.Handler
	if !p.cfg.Proxy {
		csrfHandle = csrf.Protect(csrfKey)
	}

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
	p.addRoute(http.MethodPost, v1.RouteProposalVotes,
		p.handleProposalVotes, permissionPublic, true)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret,
		permissionLogin, false)
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
	p.addRoute(http.MethodGet, v1.RouteVerifyUserPaymentTx,
		p.handleVerifyUserPaymentTx, permissionLogin, false)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted,
		permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus,
		p.handleSetProposalStatus, permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteStartVote,
		p.handleStartVote, permissionAdmin, true)

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
		MaxAge:   86400, // One day
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
				Addr:      listen,
				TLSConfig: cfg,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler)),
			}
			var mode string
			if p.cfg.Proxy {
				srv.Handler = p.router
				mode = "proxy"
			} else {
				srv.Handler = csrfHandle(p.router)
				mode = "non-proxy"
			}
			log.Infof("Listen %v: %v", mode, listen)
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
