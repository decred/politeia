package main

import (
	"bufio"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
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
)

type newUserEmailTemplateData struct {
	Link  string
	Email string
}
type resetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

// PoliteiaWWW application context
type PoliteiaWWW struct {
	cfg     *config
	store   sessions.Store
	backend *backend
}

// NewPolitieaWWW returns a new PoliteiaWWW instance
func NewPoliteiaWWW(cfg *config) (*PoliteiaWWW, error) {
	var err error
	// Create the data directory in case it does not exist.
	if err = os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}

	// Persist session cookies.
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(cfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(cfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return nil, err
		}
		log.Infof("Cookie key generated.")
	}

	sessionsDir := filepath.Join(cfg.DataDir, "sessions")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		return nil, err
	}

	store := sessions.NewFilesystemStore(sessionsDir, cookieKey)
	store.Options = defaultStoreOptions

	backend, err := NewBackend(cfg)
	if err != nil {
		return nil, err
	}

	return &PoliteiaWWW{
		cfg:     cfg,
		backend: backend,
		store:   store,
	}, nil
}

// RegisterHandlers registers PoliteiaWWW handlers in the given router
func (p *PoliteiaWWW) RegisterHandlers(router *mux.Router) {
	p.addV1Routes(router)
}

// addV1Routes registers routes in the given router (v1)
func (p *PoliteiaWWW) addV1Routes(router *mux.Router) {
	subrouter := router.PathPrefix("/v1").Subrouter()

	// not found
	subrouter.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// public routes
	subrouter.HandleFunc("/", logging(p.handleVersion)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteNewUser, p.middleware(p.handleNewUser, permissionPublic, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteVerifyNewUser, p.middleware(p.handleVerifyNewUser, permissionPublic, false)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteLogin, p.middleware(p.handleLogin, permissionPublic, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteLogout, p.middleware(p.handleLogout, permissionPublic, false)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteLogout, p.middleware(p.handleLogout, permissionPublic, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteResetPassword, p.middleware(p.handleResetPassword, permissionPublic, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteAllVetted, p.middleware(p.handleAllVetted, permissionPublic, true)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteProposalDetails, p.middleware(p.handleProposalDetails, permissionPublic, true)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RoutePolicy, p.middleware(p.handlePolicy, permissionPublic, false)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteCommentsGet, p.middleware(p.handleCommentsGet, permissionPublic, true)).Methods(http.MethodGet)

	// routes that require being logged in.
	subrouter.HandleFunc(v1.RouteSecret, p.middleware(p.handleSecret, permissionLogin, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteNewProposal, p.middleware(p.handleNewProposal, permissionLogin, true)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteUserMe, p.middleware(p.handleMe, permissionLogin, false)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteChangePassword, p.middleware(p.handleChangePassword, permissionLogin, false)).Methods(http.MethodPost)
	subrouter.HandleFunc(v1.RouteNewComment, p.middleware(p.handleNewComment, permissionLogin, true)).Methods(http.MethodPost)

	// routes that require being logged in as an admin user.
	subrouter.HandleFunc(v1.RouteAllUnvetted, p.middleware(p.handleAllUnvetted, permissionAdmin, true)).Methods(http.MethodGet)
	subrouter.HandleFunc(v1.RouteSetProposalStatus, p.middleware(p.handleSetProposalStatus, permissionAdmin, true)).Methods(http.MethodPost)
}

// Fetch remote identity
func (p *PoliteiaWWW) getIdentity() error {
	id, err := util.RemoteIdentity(false, p.cfg.RPCHost, p.cfg.RPCCert)
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("FQDN       : %v", id.Name)
	log.Infof("Nick       : %v", id.Nick)
	log.Infof("Key        : %x", id.Key)
	log.Infof("Identity   : %x", id.Identity)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	// Ask user if we like this identity
	log.Infof("Save to %v or ctrl-c to abort", p.cfg.RPCIdentityFile)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err = scanner.Err(); err != nil {
		return err
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
func RespondWithError(w http.ResponseWriter, r *http.Request, userHTTPCode int, format string, args ...interface{}) {
	if userErr, ok := args[0].(v1.UserError); ok {
		if userHTTPCode == 0 {
			userHTTPCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Debugf("RespondWithError: %v %v", int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode])
		} else {
			log.Debugf("RespondWithError: %v %v: %v", int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode],
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHTTPCode,
			v1.ErrorReply{
				ErrorCode: int64(userErr.ErrorCode),
			})
		return
	}

	if pdError, ok := args[0].(v1.PDError); ok {
		pdErrorCode := convertErrorStatusFromPD(pdError.ErrorReply.ErrorCode)
		if pdErrorCode == v1.ErrorStatusInvalid {
			errorCode := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error code from politeiad: %v",
				remoteAddr(r), r.Method, r.URL, r.Proto, errorCode, pdError.ErrorReply.ErrorCode)
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
	util.RespondWithJSON(w, http.StatusInternalServerError,
		v1.ErrorReply{
			ErrorCode: errorCode,
		})
}

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func (p *PoliteiaWWW) handleVersion(w http.ResponseWriter, r *http.Request) {
	/*
		// Get the version command.
		var v v1.Version
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&v); err != nil {
			RespondInternalError(w, r,
				"handleVersion: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	versionReply, err := json.Marshal(v1.VersionReply{
		Version: v1.PoliteiaWWWAPIVersion,
		Route:   v1.PoliteiaWWWAPIRoute,
		PubKey:  hex.EncodeToString(p.cfg.Identity.Key[:]),
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
func (p *PoliteiaWWW) handleNewUser(w http.ResponseWriter, r *http.Request) {
	// Get the new user command.
	var u v1.NewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleNewUser: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleNewUser: ProcessNewUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleVerifyNewUser handles the incoming new user verify command. It verifies
// that the user with the provided email has a verificaton token that matches
// the provided token and that the verification token has not yet expired.
func (p *PoliteiaWWW) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
	routePrefix := p.cfg.WebServerAddress

	// Get the new user verify command.
	var vnu v1.VerifyNewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vnu); err != nil {
		// The parameters may be part of the query, so check those before
		// throwing an error.
		query := r.URL.Query()
		email, emailOk := query["email"]
		token, tokenOk := query["verificationtoken"]
		if !emailOk || !tokenOk {
			log.Errorf("handleVerifyNewUser: Unmarshal %v", err)
			http.Redirect(w, r, routePrefix+v1.RouteVerifyNewUserFailure,
				http.StatusMovedPermanently)
			return
		}

		vnu.Email = email[0]
		vnu.VerificationToken = token[0]
	}
	defer r.Body.Close()

	err := p.backend.ProcessVerifyNewUser(vnu)
	if err != nil {
		userErr, ok := err.(v1.UserError)
		if ok {
			url, err := url.Parse(routePrefix + v1.RouteVerifyNewUserFailure)
			if err == nil {
				q := url.Query()
				q.Set("errorcode", string(userErr.ErrorCode))
				url.RawQuery = q.Encode()
				http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
				return
			}
		}

		log.Errorf("handleVerifyNewUser: %v", err)
		http.Redirect(w, r, routePrefix+v1.RouteVerifyNewUserFailure,
			http.StatusMovedPermanently)
		return
	}

	http.Redirect(w, r, routePrefix+v1.RouteVerifyNewUserSuccess,
		http.StatusMovedPermanently)
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *PoliteiaWWW) handleLogin(w http.ResponseWriter, r *http.Request) {
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0, "handleLogin: failed to get session: %v",
			err)
		return
	}

	// Get the login command.
	var l v1.Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&l); err != nil {
		RespondWithError(w, r, 0, "handleLogin: failed to decode: %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessLogin(l)
	if err != nil {
		RespondWithError(w, r, http.StatusForbidden,
			"handleLogin: ProcessLogin %v", err)
		return
	}

	// Mark user as logged in if there's no error.
	session.Values["email"] = l.Email
	session.Values["id"] = reply.UserID
	session.Values["authenticated"] = true
	session.Values["admin"] = reply.IsAdmin
	err = session.Save(r, w)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogin: failed to save session: %v", err)
		return
	}

	// Reply with the user information.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLogout logs the user out.  A login will be required to resume sending
// commands,
func (p *PoliteiaWWW) handleLogout(w http.ResponseWriter, r *http.Request) {
	/*
		// Get the logout command.
		var l v1.Logout
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&l); err != nil {
			RespondInternalError(w, r,
				"handleLogout: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogout: failed to get session: %v", err)
		return
	}

	// Revoke users authentication
	session.Values["email"] = ""
	session.Values["id"] = 0
	session.Values["authenticated"] = false
	session.Values["admin"] = false
	err = session.Save(r, w)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLogout: failed to save session: %v", err)
		return
	}

	// Reply with the user information.
	var reply v1.LogoutReply
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSecret is a mock handler to test privileged routes.
func (p *PoliteiaWWW) handleSecret(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secret sauce")
}

// handleMe returns logged in user information.
func (p *PoliteiaWWW) handleMe(w http.ResponseWriter, r *http.Request) {
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleMe: failed to get session: %v", err)
		return
	}

	email, oke := session.Values["email"].(string)
	isAdmin, oki := session.Values["admin"].(bool)
	if !oke || !oki {
		RespondWithError(w, r, 0,
			"handleMe: type assert oke %v oki %v", oke, oki)
		return
	}

	// Reply with the user information.
	reply := v1.MeReply{
		Email:   email,
		IsAdmin: isAdmin,
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *PoliteiaWWW) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get the email for the current session.
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: failed to get session: %v", err)
		return
	}

	email, ok := session.Values["email"].(string)
	if !ok {
		RespondWithError(w, r, 0,
			"handleChangePassword: type assert ok %v", ok)
		return
	}

	// Get the change password command.
	var cp v1.ChangePassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cp); err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessChangePassword(email, cp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: ProcessChangePassword %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *PoliteiaWWW) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Get the reset password command.
	var rp v1.ResetPassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rp); err != nil {
		RespondWithError(w, r, 0,
			"handleResetPassword: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

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
func (p *PoliteiaWWW) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	var np v1.NewProposal

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewProposal(np)
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
func (p *PoliteiaWWW) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	// Get the proposal status command.
	var sps v1.SetProposalStatus

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sps); err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessSetProposalStatus(sps)
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
func (p *PoliteiaWWW) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
	// Get the proposal details command.
	var pd v1.ProposalsDetails

	/*
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pd); err != nil {
			RespondInternalError(w, r,
				"handleProposalDetails: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	// Add the path param to the struct.
	pathParams := mux.Vars(r)
	pd.Token = pathParams["token"]

	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: failed to get session %v", err)
		return
	}

	isAdmin, _ := session.Values["admin"].(bool)
	reply, err := p.backend.ProcessProposalDetails(pd, isAdmin)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: ProcessProposalDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *PoliteiaWWW) handlePolicy(w http.ResponseWriter, r *http.Request) {
	// Get the policy command.
	var policy v1.Policy
	/*
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&policy); err != nil {
			RespondInternalError(w, r,
				"handlePolicy: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	reply := p.backend.ProcessPolicy(policy)

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleAllVetted replies with the list of vetted proposals.
func (p *PoliteiaWWW) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	// Get the all vetted command.
	var v v1.GetAllVetted

	/*
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&v); err != nil {
			RespondInternalError(w, r,
				"handleAllVetted: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	vr := p.backend.ProcessAllVetted(v)
	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleAllUnvetted replies with the list of unvetted proposals.
func (p *PoliteiaWWW) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
	// Get the all unvetted command.
	var u v1.GetAllUnvetted

	/*
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&u); err != nil {
			RespondInternalError(w, r,
				"handleAllUnvetted: Unmarshal %v", err)
			return
		}
		defer r.Body.Close()
	*/
	ur := p.backend.ProcessAllUnvetted(u)
	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleNewComment handles incomming comments.
func (p *PoliteiaWWW) handleNewComment(w http.ResponseWriter, r *http.Request) {
	var sc v1.NewComment

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	// Get session to retrieve user id
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: failed to get session: %v", err)
		return
	}
	userID, ok := session.Values["id"].(uint64)
	if !ok {
		RespondWithError(w, r, 0,
			"handleNewComment: invalid user ID: %v", err)
		return
	}

	cr, err := p.backend.ProcessComment(sc, userID)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: ProcessComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleCommentsGet handles batched comments get.
func (p *PoliteiaWWW) handleCommentsGet(w http.ResponseWriter, r *http.Request) {

	pathParams := mux.Vars(r)
	defer r.Body.Close()
	gcr, err := p.backend.ProcessCommentGet(pathParams["token"])
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: ProcessCommentGet %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gcr)
}

// handleNotFound is a generic handler for an invalid route.
func (p *PoliteiaWWW) handleNotFound(w http.ResponseWriter, r *http.Request) {
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
