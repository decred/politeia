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
		if err == database.ErrUserNotFound {
			return false, nil
		}
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
	if userErr, ok := args[0].(v1.UserError); ok {
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Debugf("RespondWithError: %v %v",
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode])
		} else {
			log.Debugf("RespondWithError: %v %v: %v",
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode],
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHttpCode,
			v1.ErrorReply{
				ErrorCode: int64(userErr.ErrorCode),
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
	// Get the new user command.
	log.Tracef("handleNewUser")
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
// that the user with the provided email has a verification token that matches
// the provided token and that the verification token has not yet expired.
func (p *politeiawww) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
	// Get the new user verify command.
	log.Tracef("handleVerifyNewUser")
	var vnu v1.VerifyNewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vnu); err != nil {
		// The parameters may be part of the query, so check those before
		// throwing an error.
		query := r.URL.Query()
		email, emailOk := query["email"]
		token, tokenOk := query["verificationtoken"]
		sig, sigOk := query["signature"]
		if !emailOk || !tokenOk || !sigOk {
			RespondWithError(w, r, 0, "could not decode URL",
				v1.UserError{
					ErrorCode: v1.ErrorStatusInvalidInput,
				})
			return
		}

		vnu.Email = email[0]
		vnu.VerificationToken = token[0]
		vnu.Signature = sig[0]
	}
	defer r.Body.Close()

	_, err := p.backend.ProcessVerifyNewUser(vnu)
	if err != nil {
		RespondWithError(w, r, 0, "handleVerifyNewUser: "+
			"ProcessVerifyNewUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.VerifyNewUserReply{})
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Get the login command.
	log.Tracef("handleLogin")
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

	activeIdentity, ok := database.ActiveIdentityString(user.Identities)
	if !ok {
		activeIdentity = ""
	}
	reply := v1.MeReply{
		IsAdmin:   user.Admin,
		UserID:    strconv.FormatUint(user.ID, 10),
		Email:     user.Email,
		PublicKey: activeIdentity,
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get the change password command.
	log.Tracef("handleChangePassword")
	var cp v1.ChangePassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cp); err != nil {
		RespondWithError(w, r, 0,
			"handleChangePassword: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

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
	// Get the reset password command.
	log.Tracef("handleResetPassword")
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
func (p *politeiawww) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	log.Tracef("handleNewProposal")
	var np v1.NewProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

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
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

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

	isAdmin, err := p.isAdmin(r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: isAdmin %v", err)
		return
	}
	reply, err := p.backend.ProcessProposalDetails(pd, isAdmin)
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
	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleAllVetted replies with the list of vetted proposals.
func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	// Get the all vetted command.
	log.Tracef("handleAllVetted")
	var v v1.GetAllVetted
	vr := p.backend.ProcessAllVetted(v)
	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleAllUnvetted replies with the list of unvetted proposals.
func (p *politeiawww) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
	// Get the all unvetted command.
	log.Tracef("handleAllUnvetted")
	var u v1.GetAllUnvetted
	ur := p.backend.ProcessAllUnvetted(u)
	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleNewComment handles incomming comments.
func (p *politeiawww) handleNewComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewComment")
	var sc v1.NewComment

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

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

	var csrfHandle func(http.Handler) http.Handler
	if !p.cfg.Proxy {
		// We don't persist connections to generate a new key every
		// time we restart.
		csrfKey, err := util.Random(32)
		if err != nil {
			return err
		}
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
	p.router.HandleFunc("/", logging(p.handleVersion)).Methods(http.MethodGet)
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)
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
	p.addRoute(http.MethodGet, v1.RouteProposalDetails, p.
		handleProposalDetails, permissionPublic, true)
	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy,
		permissionPublic, false)
	p.addRoute(http.MethodGet, v1.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic, true)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret,
		permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteNewProposal, p.handleNewProposal,
		permissionLogin, true)
	p.addRoute(http.MethodGet, v1.RouteUserMe, p.handleMe, permissionLogin,
		false)
	p.addRoute(http.MethodPost, v1.RouteChangePassword,
		p.handleChangePassword, permissionLogin, false)
	p.addRoute(http.MethodPost, v1.RouteNewComment,
		p.handleNewComment, permissionLogin, true)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted,
		permissionAdmin, true)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus,
		p.handleSetProposalStatus, permissionAdmin, true)

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
