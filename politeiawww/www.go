package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/dajohi/goemail"
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

var (
	// versionReply is the cached version reply.
	versionReply []byte
)

// politeiawww application context.
type politeiawww struct {
	cfg    *config
	router *mux.Router

	store *sessions.CookieStore

	backend *backend
}

// init sets default values at startup.
func init() {
	var err error
	versionReply, err = json.Marshal(v1.Version{
		Version: v1.PoliteiaWWWAPIVersion,
		Route:   v1.PoliteiaWWWAPIRoute,
	})
	if err != nil {
		panic(fmt.Sprintf("versionReply: %v", err))
	}
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

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
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
	// Get new user command.
	var u v1.NewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		log.Errorf("handleNewUser: Unmarshal %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewUser(u)
	if err != nil {
		log.Errorf("handleNewUser: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	// Email the verification token if the email server is set up.
	if p.cfg.SMTP != nil {
		from := "noreply@decred.org"
		subject := "Politeia Registration - Verify Your Email"
		body := "<p>You must verify your email to complete your registration.</p>" +
			"<p>Enter this code to verify your email: <span style=\"font-weight: bold\">" + reply.VerificationToken + "</span></p>" +
			"<p>You are receiving this email because this email address was used to register for Politeia.</p>"

		msg := goemail.NewHTMLMessage(from, subject, body)
		msg.AddTo(u.Email)

		if err := p.cfg.SMTP.Send(msg); err != nil {
			log.Errorf("handleNewUser: SMTP.Send %v", err)
		}
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleVerifyNewUser handles the incoming new user verify command. It verifies
// that the user with the provided email has a verificaton token that matches
// the provided token and that the verification token has not yet expired.
func (p *politeiawww) handleVerifyNewUser(w http.ResponseWriter, r *http.Request) {
	// Get new user verify command.
	var u v1.VerifyNewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		log.Errorf("handleVerifyNewUser: Unmarshal %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	defer r.Body.Close()

	err := p.backend.ProcessVerifyNewUser(u)
	if err != nil {
		log.Errorf("handleVerifyNewUser: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
}

// handleLogin handles the incoming login command.  It verifies that the user
// exists and the accompanying password.  On success a cookie is added to the
// gorilla sessions that must be returned on subsequent calls.
func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := p.store.Get(r, v1.CookieSession)

	// Get login command.
	var l v1.Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&l); err != nil {
		log.Errorf("handleLogin: Unmarshal %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	defer r.Body.Close()

	user, err := p.backend.ProcessLogin(l)
	if err != nil {
		log.Errorf("handleLogin: %v", err)

		var statusCode int
		if err == v1.ErrInvalidEmailOrPassword {
			statusCode = http.StatusUnauthorized
		} else {
			statusCode = http.StatusForbidden
		}

		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	// Mark user as logged in.
	session.Values["authenticated"] = true
	session.Values["admin"] = user.Admin
	session.Save(r, w)
}

// handleLogout logs the user out.  A login will be required to resume sending
// commands,
func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := p.store.Get(r, v1.CookieSession)

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["admin"] = false
	session.Save(r, w)
}

// handleSecret is a mock handler to test routes.
func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secret sauce")
}

// handleNewProposal handles the incoming new proposal command.
func (p *politeiawww) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get new proposal command.
	var np v1.NewProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		log.Errorf("handleNewProposal: Unmarshal %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessNewProposal(np)
	if err != nil {
		log.Errorf("handleNewProposal: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
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
		log.Errorf("handleSetProposalStatus: Unmarshal %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	defer r.Body.Close()

	reply, err := p.backend.ProcessSetProposalStatus(sps)
	if err != nil {
		log.Errorf("handleSetProposalStatus: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleProposalDetails handles the incoming proposal details command. It fetches
// the complete details for an existing proposal.
func (p *politeiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
	pathParams := mux.Vars(r)
	reply, err := p.backend.ProcessProposalDetails(pathParams["token"])
	if err != nil {
		log.Errorf("handleProposalDetails: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	reply := p.backend.ProcessPolicy()

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleAllVetted replies with the list of vetted proposals.
func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	ur := p.backend.ProcessAllVetted()
	util.RespondWithJSON(w, http.StatusOK, ur)
}

// handleAllUnvetted replies with the list of unvetted proposals.
func (p *politeiawww) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
	ur := p.backend.ProcessAllUnvetted()
	util.RespondWithJSON(w, http.StatusOK, ur)
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
		if err := p.getIdentity(); err != nil {
			return err
		}
		return nil
	}

	p.backend, err = NewBackend(p.cfg)
	if err != nil {
		return err
	}

	// Fetch the inventory from politeiad and cache it.
	if err := p.backend.LoadInventory(); err != nil {
		return err
	}

	// We don't persist connections to generate a new key every time we
	// restart.
	csrfKey, err := util.Random(32)
	if err != nil {
		return err
	}
	csrfHandle := csrf.Protect(csrfKey)
	p.router = mux.NewRouter()
	// Static content.
	p.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/",
		http.FileServer(http.Dir("."))))

	// Public routes.
	p.router.HandleFunc("/", logging(p.handleVersion)).Methods(http.MethodGet)
	p.addRoute(http.MethodPost, v1.RouteNewUser, p.handleNewUser, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteVerifyNewUser, p.handleVerifyNewUser, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogin, p.handleLogin, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogout, p.handleLogout, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteAllVetted, p.handleAllVetted, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteProposalDetails, p.handleProposalDetails, permissionPublic)
	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy, permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteNewProposal, p.handleNewProposal, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted, permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus, p.handleSetProposalStatus, permissionAdmin)

	// Since we don't persist connections also generate a new cookie key on
	// startup.
	cookieKey, err := util.Random(32)
	if err != nil {
		return err
	}
	p.store = sessions.NewCookieStore(cookieKey)
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
				Handler:   csrfHandle(p.router),
				TLSConfig: cfg,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler), 0),
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
