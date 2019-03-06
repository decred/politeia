// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/elliptic"
	"crypto/tls"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/decred/politeia/politeiad/cache/cockroachdb"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionLogin
	permissionAdmin

	csrfKeyLength = 32
	sessionMaxAge = 86400 //One day
)

var (
	// ErrSessionUUIDNotFound is emitted when a UUID value is not found
	// in a session and indicates that the user is not logged in.
	ErrSessionUUIDNotFound = errors.New("session UUID not found")
)

// wsContext is the websocket context. If uuid == "" then it is an
// unauthenticated websocket.
type wsContext struct {
	uuid          string
	rid           string
	conn          *websocket.Conn
	wg            sync.WaitGroup
	subscriptions map[string]struct{}
	errorC        chan v1.WSError
	pingC         chan struct{}
	done          chan struct{} // SHUT...DOWN...EVERYTHING...
}

func (w *wsContext) String() string {
	u := w.uuid
	if u == "" {
		u = "anon"
	}
	return u + " " + w.rid
}

func (w *wsContext) IsAuthenticated() bool {
	return w.uuid != ""
}

// getSession returns the active cookie session.
func (p *politeiawww) getSession(r *http.Request) (*sessions.Session, error) {
	return p.store.Get(r, v1.CookieSession)
}

// getSessionUUID returns the uuid address of the currently logged in user from
// the session store.
func (p *politeiawww) getSessionUUID(r *http.Request) (string, error) {
	session, err := p.getSession(r)
	if err != nil {
		return "", err
	}

	id, ok := session.Values["uuid"].(string)
	if !ok {
		return "", ErrSessionUUIDNotFound
	}
	log.Tracef("getSessionUUID: %v", session.ID)

	return id, nil
}

// getSessionUser retrieves the current session user from the database.
func (p *politeiawww) getSessionUser(w http.ResponseWriter, r *http.Request) (*user.User, error) {
	id, err := p.getSessionUUID(r)
	if err != nil {
		return nil, err
	}

	log.Tracef("getSessionUser: %v", id)
	pid, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	user, err := p.db.UserGetById(pid)
	if err != nil {
		return nil, err
	}

	if user.Deactivated {
		p.removeSession(w, r)
		return nil, v1.UserError{
			ErrorCode: v1.ErrorStatusNotLoggedIn,
		}
	}

	return user, nil
}

// setSessionUserID sets the "uuid" session key to the provided value.
func (p *politeiawww) setSessionUserID(w http.ResponseWriter, r *http.Request, id string) error {
	log.Tracef("setSessionUserID: %v %v", id, v1.CookieSession)
	session, err := p.getSession(r)
	if err != nil {
		return err
	}

	session.Values["uuid"] = id
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
func (p *politeiawww) isAdmin(w http.ResponseWriter, r *http.Request) (bool, error) {
	user, err := p.getSessionUser(w, r)
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
		log.Infof("Press enter to save to %v or ctrl-c to abort",
			p.cfg.RPCIdentityFile)
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
			log.Errorf("RespondWithError: %v %v %v",
				remoteAddr(r),
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode])
		} else {
			log.Errorf("RespondWithError: %v %v %v: %v",
				remoteAddr(r),
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

	reply, err := p.ProcessNewUser(u)
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

	_, err = p.ProcessVerifyNewUser(vnu)
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

	rvr, err := p.ProcessResendVerification(&rv)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUpdateUserKey: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessUpdateUserKey(user, u)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUpdateUserKey: getSessionUser %v", err)
		return
	}

	_, err = p.ProcessVerifyUpdateUserKey(user, vuu)
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

	reply, err := p.ProcessLogin(l)
	if err != nil {
		RespondWithError(w, r, http.StatusUnauthorized,
			"handleLogin: ProcessLogin %v", err)
		return
	}

	// Mark user as logged in if there's no error.
	err = p.setSessionUserID(w, r, reply.UserID)
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

	_, err := p.getSessionUser(w, r)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: getSessionUser %v", err)
		return
	}

	reply, err := p.CreateLoginReply(user, user.LastLoginTime)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangeUsername: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessChangeUsername(user.Email, cu)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessChangePassword(user.Email, cp)
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

	rpr, err := p.ProcessResetPassword(rp)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessProposalPaywallDetails(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: ProcessProposalPaywallDetails  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleProposalPaywallPayment returns the payment details for a pending
// proposal paywall payment.
func (p *politeiawww) handleProposalPaywallPayment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalPaywallPayment")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallPayment: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessProposalPaywallPayment(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallPayment: ProcessProposalPaywallPayment  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) websocketPing(id string) {
	log.Tracef("websocketPing %v", id)
	defer log.Tracef("websocketPing exit %v", id)

	p.wsMtx.RLock()
	defer p.wsMtx.RUnlock()

	for _, v := range p.ws[id] {
		if _, ok := v.subscriptions[v1.WSCPing]; !ok {
			continue
		}

		select {
		case v.pingC <- struct{}{}:
		default:
		}
	}
}

func (p *politeiawww) handleWebsocketRead(wc *wsContext) {
	defer wc.wg.Done()

	log.Tracef("handleWebsocketRead %v", wc)
	defer log.Tracef("handleWebsocketRead exit %v", wc)

	for {
		cmd, id, payload, err := util.WSRead(wc.conn)
		if err != nil {
			log.Tracef("handleWebsocketRead read %v %v", wc, err)
			close(wc.done) // force handlers to quit
			return
		}
		switch cmd {
		case v1.WSCSubscribe:
			subscribe, ok := payload.(v1.WSSubscribe)
			if !ok {
				// We are treating this a hard error so that
				// the client knows they sent in something
				// wrong.
				log.Errorf("handleWebsocketRead invalid "+
					"subscribe type %v %v", wc,
					spew.Sdump(payload))
				return
			}

			//log.Tracef("subscribe: %v %v", wc.uuid,
			//	spew.Sdump(subscribe))

			subscriptions := make(map[string]struct{})
			var errors []string
			for _, v := range subscribe.RPCS {
				if !util.ValidSubscription(v) {
					log.Tracef("invalid subscription %v %v",
						wc, v)
					errors = append(errors,
						fmt.Sprintf("invalid "+
							"subscription %v", v))
					continue
				}
				if util.SubsciptionReqAuth(v) &&
					!wc.IsAuthenticated() {
					log.Tracef("requires auth %v %v", wc, v)
					errors = append(errors,
						fmt.Sprintf("requires "+
							"authentication %v", v))
					continue
				}
				subscriptions[v] = struct{}{}
			}

			if len(errors) == 0 {
				// Replace old subscriptions
				p.wsMtx.Lock()
				wc.subscriptions = subscriptions
				p.wsMtx.Unlock()
			} else {
				wc.errorC <- v1.WSError{
					Command: v1.WSCSubscribe,
					ID:      id,
					Errors:  errors,
				}
			}
		}
	}
}

func (p *politeiawww) handleWebsocketWrite(wc *wsContext) {
	defer wc.wg.Done()
	log.Tracef("handleWebsocketWrite %v", wc)
	defer log.Tracef("handleWebsocketWrite exit %v", wc)

	for {
		var (
			cmd, id string
			payload interface{}
		)
		select {
		case <-wc.done:
			return
		case e, ok := <-wc.errorC:
			if !ok {
				log.Tracef("handleWebsocketWrite error not ok"+
					" %v", wc)
				return
			}
			cmd = v1.WSCError
			id = e.ID
			payload = e
		case _, ok := <-wc.pingC:
			if !ok {
				log.Tracef("handleWebsocketWrite ping not ok"+
					" %v", wc)
				return
			}
			cmd = v1.WSCPing
			id = ""
			payload = v1.WSPing{Timestamp: time.Now().Unix()}
		}

		err := util.WSWrite(wc.conn, cmd, id, payload)
		if err != nil {
			log.Tracef("handleWebsocketWrite write %v %v", wc, err)
			return
		}
	}
}

func (p *politeiawww) handleWebsocket(w http.ResponseWriter, r *http.Request, id string) {
	log.Tracef("handleWebsocket: %v", id)
	defer log.Tracef("handleWebsocket exit: %v", id)

	// Setup context
	wc := wsContext{
		uuid:          id,
		subscriptions: make(map[string]struct{}),
		pingC:         make(chan struct{}),
		errorC:        make(chan v1.WSError),
		done:          make(chan struct{}),
	}

	var upgrader = websocket.Upgrader{
		EnableCompression: true,
	}

	var err error
	wc.conn, err = upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Could not open websocket connection",
			http.StatusBadRequest)
		return
	}
	defer wc.conn.Close() // causes read to exit as well

	// Create and assign session to map
	p.wsMtx.Lock()
	if _, ok := p.ws[id]; !ok {
		p.ws[id] = make(map[string]*wsContext)
	}
	for {
		rid, err := util.Random(16)
		if err != nil {
			p.wsMtx.Unlock()
			http.Error(w, "Could not create random session id",
				http.StatusBadRequest)
			return
		}
		wc.rid = hex.EncodeToString(rid)
		if _, ok := p.ws[id][wc.rid]; !ok {
			break
		}
	}
	p.ws[id][wc.rid] = &wc
	p.wsMtx.Unlock()

	// Reads
	wc.wg.Add(1)
	go p.handleWebsocketRead(&wc)

	// Writes
	wc.wg.Add(1)
	go p.handleWebsocketWrite(&wc)

	// XXX Example of a server side notifcation. Remove once other commands
	// can be used as examples.
	// time.Sleep(2 * time.Second)
	// p.websocketPing(id)

	wc.wg.Wait()

	// Remove session id
	p.wsMtx.Lock()
	delete(p.ws[id], wc.rid)
	if len(p.ws[id]) == 0 {
		// Remove uuid since it was the last one
		delete(p.ws, id)
	}
	p.wsMtx.Unlock()
}

func (p *politeiawww) handleUnauthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	// We are retrieving the uuid here to make sure it is NOT set. This
	// check looks backwards but is correct.
	id, err := p.getSessionUUID(r)
	if err != nil && err != ErrSessionUUIDNotFound {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}
	if id != "" {
		http.Error(w, "Invalid session uuid", http.StatusBadRequest)
		return
	}
	log.Tracef("handleUnauthenticatedWebsocket: %v", id)
	defer log.Tracef("handleUnauthenticatedWebsocket exit: %v", id)

	p.handleWebsocket(w, r, id)
}

func (p *politeiawww) handleAuthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	id, err := p.getSessionUUID(r)
	if err != nil {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}

	log.Tracef("handleAuthenticatedWebsocket: %v", id)
	defer log.Tracef("handleAuthenticatedWebsocket exit: %v", id)

	p.handleWebsocket(w, r, id)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessNewProposal(np, user)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: getSessionUser %v", err)
		return
	}

	// Set status
	reply, err := p.ProcessSetProposalStatus(sps, user)
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
	var pd v1.ProposalsDetails

	// get version from query string parameters
	err := util.ParseGetParams(r, &pd)
	if err != nil {
		RespondWithError(w, r, 0, "handleProposalDetails: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	// Get proposal token from path parameters
	pathParams := mux.Vars(r)
	pd.Token = pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != ErrSessionUUIDNotFound {
			RespondWithError(w, r, 0,
				"handleProposalDetails: getSessionUser %v", err)
			return
		}
	}
	reply, err := p.ProcessProposalDetails(pd, user)
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
	reply := ProcessPolicy()
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

	vr, err := p.ProcessAllVetted(v)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllVetted: ProcessAllVetted %v", err)
		return
	}

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

	ur, err := p.ProcessAllUnvetted(u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllUnvetted: ProcessAllUnvetted %v", err)
		return
	}

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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: getSessionUser %v", err)
		return
	}

	cr, err := p.ProcessNewComment(sc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: ProcessNewComment: %v", err)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLikeComment: getSessionUser %v", err)
		return
	}

	cr, err := p.ProcessLikeComment(lc, user)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCensorComment: getSessionUser %v", err)
		return
	}

	cr, err := p.ProcessCensorComment(cc, user)
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
	token := pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != ErrSessionUUIDNotFound {
			RespondWithError(w, r, 0,
				"handleCommentsGet: getSessionUser %v", err)
			return
		}
	}
	gcr, err := p.ProcessCommentsGet(token, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: ProcessCommentsGet %v", err)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyUserPayment: getSessionUser %v", err)
		return
	}

	vuptr, err := p.ProcessVerifyUserPayment(user, vupt)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: getSessionUser %v", err)
		return
	}

	reply, err := ProcessUserProposalCredits(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: ProcessUserProposalCredits  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (p *politeiawww) handleUserPaymentsRescan(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserPaymentsRescan")

	var upr v1.UserPaymentsRescan
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&upr); err != nil {
		RespondWithError(w, r, 0, "handleUserPaymentsRescan: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.ProcessUserPaymentsRescan(upr)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserPaymentsRescan: ProcessUserPaymentsRescan:  %v",
			err)
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		// since having a logged in user isn't required, simply log the error
		log.Infof("handleUserProposals: could not get session user %v", err)
	}

	upr, err := p.ProcessUserProposals(
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

	avr, err := p.ProcessActiveVote()
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

	avr, err := p.ProcessCastVotes(&cv)
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

	vrr, err := p.ProcessVoteResults(token)
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
	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: getSessionUser %v", err)
		return
	}
	avr, err := p.ProcessAuthorizeVote(av, user)
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

	user, err := p.getSessionUser(w, r)
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

	svr, err := p.ProcessStartVote(sv, user)
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
		RespondWithError(w, r, 0, "handleUserDetails: ParseUint",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		// since having a logged in user isn't required, simply log the error
		log.Infof("handleUserDetails: could not get session user %v", err)
	}

	udr, err := p.ProcessUserDetails(&ud,
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

// handleUsers handles fetching a list of users.
func (p *politeiawww) handleUsers(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUsers")

	var u v1.Users
	err := util.ParseGetParams(r, &u)
	if err != nil {
		RespondWithError(w, r, 0, "handleUsers: ParseGetParams",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	ur, err := p.ProcessUsers(&u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUsers: ProcessUsers %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleManageUser handles editing a user's details.
func (p *politeiawww) handleManageUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleManageUser")

	var mu v1.ManageUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&mu); err != nil {
		RespondWithError(w, r, 0, "handleManageUser: unmarshal", v1.UserError{
			ErrorCode: v1.ErrorStatusInvalidInput,
		})
		return
	}

	adminUser, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleManageUser: getSessionUser %v", err)
		return
	}

	mur, err := p.ProcessManageUser(&mu, adminUser)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleManageUser: ProcessManageUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, mur)
}

// handleEditUser handles editing a user's preferences.
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

	adminUser, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0, "handleEditUser: getSessionUser %v", err)
		return
	}

	eur, err := p.ProcessEditUser(&eu, adminUser)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditUser: ProcessEditUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, eur)
}

// handleGetAllVoteStatus returns the voting status of all public proposals.
func (p *politeiawww) handleGetAllVoteStatus(w http.ResponseWriter, r *http.Request) {
	gasvr, err := p.ProcessGetAllVoteStatus()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalsVotingStatus: ProcessProposalsVotingStatus %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, gasvr)
}

// handleVoteStatus returns the vote status for a given proposal.
func (p *politeiawww) handleVoteStatus(w http.ResponseWriter, r *http.Request) {
	pathParams := mux.Vars(r)
	vsr, err := p.ProcessVoteStatus(pathParams["token"])
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: ProcessCommentGet %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, vsr)
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

	uclr, err := p.ProcessUserCommentsLikes(user, token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserCommentsLikes: processUserCommentsLikes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, uclr)
}

// handleEditProposal attempts to edit a proposal
func (p *politeiawww) handleEditProposal(w http.ResponseWriter, r *http.Request) {
	var ep v1.EditProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ep); err != nil {
		RespondWithError(w, r, 0, "handleEditProposal: unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: getSessionUser %v", err)
		return
	}

	log.Debugf("handleEditProposal: %v", ep.Token)

	epr, err := p.ProcessEditProposal(ep, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: ProcessEditProposal %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, epr)
}

// handleProposalsStats returns the counting of proposals aggrouped by each proposal status
func (p *politeiawww) handleProposalsStats(w http.ResponseWriter, r *http.Request) {
	psr, err := p.ProcessProposalsStats()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalsStats: ProcessProposalsStats %v", err)
		return
	}
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

// addRoute sets up a handler for a specific method+route. If methos is not
// specified it adds a websocket.
func (p *politeiawww) addRoute(method string, route string, handler http.HandlerFunc, perm permission) {
	fullRoute := v1.PoliteiaWWWAPIRoute + route

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

	if method == "" {
		// Websocket
		log.Tracef("Adding websocket: %v", fullRoute)
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler)
	} else {
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	}
}

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
//
// XXX doesn't belong in this file but stuff it here for now.
func (p *politeiawww) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody []byte
		err         error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := p.cfg.RPCHost + route

	if p.client == nil {
		p.client, err = util.NewClient(false, p.cfg.RPCCert)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.RPCUser, p.cfg.RPCPass)
	r, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var pdErrorReply v1.PDErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pdErrorReply); err != nil {
			return nil, err
		}

		return nil, v1.PDError{
			HTTPCode:   r.StatusCode,
			ErrorReply: pdErrorReply,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
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

	log.Infof("Version : %v", version.String())
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

	if loadedCfg.MailHost == "" {
		log.Infof("Email   : DISABLED")
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
		cfg:       loadedCfg,
		ws:        make(map[string]map[string]*wsContext),
		templates: make(map[string]*template.Template),

		// XXX reevaluate where this goes
		userPubkeys:     make(map[string]string),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentScores:   make(map[string]int64),
		params:          activeNetParams.Params,
	}

	// Check if this command is being run to fetch the identity.
	if p.cfg.FetchIdentity {
		return p.getIdentity()
	}

	// Setup email
	smtp, err := newSMTP(p.cfg.MailHost, p.cfg.MailUser,
		p.cfg.MailPass, p.cfg.MailAddress)
	if err != nil {
		return fmt.Errorf("unable to initialize SMTP client: %v",
			err)
	}
	p.smtp = smtp

	// Get plugins from politeiad
	p.plugins, err = p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Setup cache connection
	cockroachdb.UseLogger(cockroachdbLog)
	net := filepath.Base(p.cfg.DataDir)
	p.cache, err = cockroachdb.New(cockroachdb.UserPoliteiawww,
		p.cfg.CacheHost, net, p.cfg.CacheRootCert, p.cfg.CacheCert,
		p.cfg.CacheKey)
	if err != nil {
		if err == cache.ErrWrongVersion {
			err = fmt.Errorf("wrong cache version, restart politeiad " +
				"to rebuild the cache")
		}
		return err
	}

	// Register plugins with cache
	for _, v := range p.plugins {
		cp := convertPluginToCache(v)
		err = p.cache.RegisterPlugin(cp)
		if err == cache.ErrWrongPluginVersion {
			return fmt.Errorf("%v plugin wrong version.  The "+
				"cache needs to be rebuilt.", v.ID)
		} else if err != nil {
			return fmt.Errorf("cache register plugin '%v': %v",
				v.ID, err)
		}

		log.Infof("Registered plugin: %v", v.ID)
	}

	// Setup database.
	// localdb.UseLogger(localdbLog)
	db, err := localdb.New(p.cfg.DataDir)
	if err != nil {
		return err
	}
	p.db = db

	// Setup pubkey-userid map
	err = p.initUserPubkeys()
	if err != nil {
		return err
	}

	// Setup comment scores map
	err = p.initCommentScores()
	if err != nil {
		return fmt.Errorf("initCommentScore: %v", err)
	}

	// Setup events
	p.initEventManager()

	// Set up the code that checks for paywall payments.
	err = p.initPaywallChecker()
	if err != nil {
		return err
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

	switch p.cfg.Mode {
	case politeiaWWWMode:
		p.setPoliteiaWWWRoutes()
	default:
		return fmt.Errorf("Unknown mode %v:", p.cfg.Mode)
	}

	// XXX setup user routes
	p.setUserWWWRoutes()

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
		SameSite: http.SameSiteStrictMode,
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
