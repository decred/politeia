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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
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

// Fetch remote identity
func (p *politeiawww) getIdentity() error {
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

// RespondInternalError returns an HTTP '500 Internal Server Error' to the
// client that is accompanied with a JSON InternalServerError struct that
// contains a correlatable error.  In addition it logs a caller specified
// error.
func RespondInternalError(w http.ResponseWriter, r *http.Request, format string, args ...interface{}) {
	errorCode := time.Now().Unix()
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", remoteAddr(r),
		r.Method, r.URL, r.Proto, errorCode)
	log.Errorf(ec+format, args...)
	util.RespondWithJSON(w, http.StatusInternalServerError,
		v1.InternalServerError{
			Error: fmt.Sprintf("Internal server error code: %v",
				errorCode),
		})
}

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
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
		Version:  v1.PoliteiaWWWAPIVersion,
		Route:    v1.PoliteiaWWWAPIRoute,
		Identity: hex.EncodeToString(p.cfg.Identity.Identity[:]),
	})
	if err != nil {
		RespondInternalError(w, r,
			"handleVersion: marshal %v", err)
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
	var u v1.NewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondInternalError(w, r,
			"handleNewUser: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewUser(u)
	if err != nil {
		RespondInternalError(w, r,
			"handleNewUser: ProcessNewUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleVerifyNewUser handles the incoming new user verify command. It verifies
// that the user with the provided email has a verificaton token that matches
// the provided token and that the verification token has not yet expired.
func (p *politeiawww) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
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

	status, err := p.backend.ProcessVerifyNewUser(vnu)
	if err != nil {
		log.Errorf("handleVerifyNewUser: %v", err)
		http.Redirect(w, r, routePrefix+v1.RouteVerifyNewUserFailure,
			http.StatusMovedPermanently)
		return
	}
	if status != v1.StatusSuccess {
		url, err := url.Parse(routePrefix + v1.RouteVerifyNewUserFailure)
		if err != nil {
			log.Errorf("handleVerifyNewUser: url.Parse %v", err)
			http.Redirect(w, r,
				routePrefix+v1.RouteVerifyNewUserFailure,
				http.StatusMovedPermanently)
			return
		}

		q := url.Query()
		q.Set("errorcode", string(status))
		url.RawQuery = q.Encode()
		http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
		return
	}

	http.Redirect(w, r, routePrefix+v1.RouteVerifyNewUserSuccess,
		http.StatusMovedPermanently)
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondInternalError(w, r,
			"handleLogin: failed to get session: %v", err)
		return
	}

	// Get the login command.
	var l v1.Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&l); err != nil {
		RespondInternalError(w, r,
			"handleLogin: failed to decode: %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessLogin(l)
	if err != nil {
		log.Errorf("handleLogin: %v", err)
		util.RespondWithJSON(w, http.StatusForbidden, reply)
		return
	}

	// Mark user as logged in if there's no error.
	if reply.ErrorCode == v1.StatusSuccess {
		session.Values["email"] = l.Email
		session.Values["authenticated"] = true
		session.Values["admin"] = reply.IsAdmin
		err = session.Save(r, w)
		if err != nil {
			RespondInternalError(w, r,
				"handleLogin: failed to save session: %v", err)
			return
		}
	}

	// Reply with the user information.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLogout logs the user out.  A login will be required to resume sending
// commands,
func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
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
		RespondInternalError(w, r,
			"handleLogout: failed to get session: %v", err)
		return
	}

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["admin"] = false
	err = session.Save(r, w)
	if err != nil {
		RespondInternalError(w, r,
			"handleLogout: failed to save session: %v", err)
		return
	}

	// Reply with the user information.
	reply := v1.LogoutReply{
		ErrorCode: v1.StatusSuccess,
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSecret is a mock handler to test privileged routes.
func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secret sauce")
}

// handleMe returns logged in user information.
func (p *politeiawww) handleMe(w http.ResponseWriter, r *http.Request) {
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondInternalError(w, r,
			"handleMe: failed to get session: %v", err)
		return
	}

	email, oke := session.Values["email"].(string)
	isAdmin, oki := session.Values["admin"].(bool)
	if !oke || !oki {
		RespondInternalError(w, r,
			"handleMe: type assert oke %v oki %v", oke, oki)
		return
	}

	// Reply with the user information.
	reply := v1.MeReply{
		Email:     email,
		IsAdmin:   isAdmin,
		ErrorCode: v1.StatusSuccess,
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get the email for the current session.
	session, err := p.store.Get(r, v1.CookieSession)
	if err != nil {
		RespondInternalError(w, r,
			"handleChangePassword: failed to get session: %v", err)
		return
	}

	email, ok := session.Values["email"].(string)
	if !ok {
		RespondInternalError(w, r,
			"handleChangePassword: type assert ok %v", ok)
		return
	}

	// Get the change password command.
	var cp v1.ChangePassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cp); err != nil {
		RespondInternalError(w, r,
			"handleChangePassword: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessChangePassword(email, cp)
	if err != nil {
		RespondInternalError(w, r,
			"handleChangePassword: %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Get the reset password command.
	var rp v1.ResetPassword
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rp); err != nil {
		RespondInternalError(w, r,
			"handleResetPassword: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	rpr, err := p.backend.ProcessResetPassword(rp)
	if err != nil {
		RespondInternalError(w, r,
			"handleResetPassword: %v", err)
		return
	}

	// Reply with the error code.
	util.RespondWithJSON(w, http.StatusOK, rpr)
}

// handleNewProposal handles the incoming new proposal command.
func (p *politeiawww) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	var np v1.NewProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		RespondInternalError(w, r,
			"handleNewProposal: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewProposal(np)
	if err != nil {
		RespondInternalError(w, r,
			"handleNewProposal: %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSetProposalStatus handles the incoming set proposal status command.
// It's used for either publishing or censoring a proposal.
func (p *politeiawww) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	// Get the proposal status command.
	var sps v1.SetProposalStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sps); err != nil {
		RespondInternalError(w, r,
			"handleSetProposalStatus: Unmarshal %v", err)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessSetProposalStatus(sps)
	if err != nil {
		RespondInternalError(w, r,
			"handleSetProposalStatus: %v", err)
		return
	}

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleProposalDetails handles the incoming proposal details command. It fetches
// the complete details for an existing proposal.
func (p *politeiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
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
		RespondInternalError(w, r,
			"handleProposalDetails: failed to get session: %v", err)
		return
	}

	isAdmin, ok := session.Values["admin"].(bool)
	if !ok {
		RespondInternalError(w, r,
			"handleProposalDetails: type assert ok %v", ok)
		return
	}

	reply, err := p.backend.ProcessProposalDetails(pd, isAdmin)
	if err != nil {
		RespondInternalError(w, r,
			"handleProposalDetails: %v", err)
		return
	}
	// XXX don't love checking err and ErrorCode
	if reply.ErrorCode != v1.StatusSuccess {
		util.RespondWithJSON(w, http.StatusBadRequest, reply)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
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
func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
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
func (p *politeiawww) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
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

	util.RespondWithJSON(w, http.StatusNotFound, nil)
}

// addRoute sets up a handler for a specific method+route.
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

	// Fetch the inventory from politeiad and cache it.
	if err := p.backend.LoadInventory(); err != nil {
		return err
	}

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
	p.addRoute(http.MethodPost, v1.RouteNewUser, p.handleNewUser, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteVerifyNewUser, p.handleVerifyNewUser, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogin, p.handleLogin, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteLogout, p.handleLogout, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogout, p.handleLogout, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteResetPassword, p.handleResetPassword, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteAllVetted, p.handleAllVetted, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteProposalDetails, p.handleProposalDetails, permissionPublic)
	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy, permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteNewProposal, p.handleNewProposal, permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteUserMe, p.handleMe, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteChangePassword, p.handleChangePassword, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted, permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus, p.handleSetProposalStatus, permissionAdmin)

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
