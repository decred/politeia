package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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

	db database.Database
}

// init sets default values at startup.
func init() {
	var err error
	versionReply, err = json.Marshal(v1.Version{
		Version: v1.PoliteiaAPIVersion,
		Route:   v1.PoliteiaAPIRoute,
	})
	if err != nil {
		panic(fmt.Sprintf("versionReply: %v", err))
	}
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

	// Get user from db.
	u, err := p.db.UserGet(l.Email)
	if err != nil {
		log.Errorf("handleLogin: UserGet %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	// Authenticate the user.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		log.Errorf("handleLogin: CompareHashAndPassword %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	// Mark user as logged in.
	session.Values["authenticated"] = true
	session.Save(r, w)

	// Get and set the CSRF token and pass it in the CSRF header.
	w.Header().Set(v1.CsrfToken, csrf.Token(r))
}

// handleLogout logs the user out.  A login will be required to resume sending
// commands,
func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := p.store.Get(r, v1.CookieSession)

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

// handleSecret is a mock handler to test routes.
func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secret sauce")
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

		err := util.GenCertPair("politeiadwww", loadedCfg.HTTPSCert,
			loadedCfg.HTTPSKey)
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

	// Setup backend.
	localdb.UseLogger(localdbLog)
	p.db, err = localdb.New(loadedCfg.DataDir)
	if err != nil {
		return err
	}
	// XXX
	//hashedPassword, err := bcrypt.GenerateFromPassword([]byte("sikrit!"),
	//	bcrypt.DefaultCost)
	//if err != nil {
	//}
	//u := database.User{
	//	Email:          "moo@moo.com",
	//	HashedPassword: hashedPassword,
	//	Admin:          true,
	//}
	//err = p.db.UserNew(u)
	//if err != nil {
	//	return err
	//}

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

	// Unauthenticated commands
	p.router.HandleFunc("/", logging(p.handleVersion)).Methods("GET")
	p.router.HandleFunc(v1.PoliteiaAPIRoute+v1.RouteLogin,
		logging(p.handleLogin)).Methods("POST")
	p.router.HandleFunc(v1.PoliteiaAPIRoute+v1.RouteLogout,
		logging(p.handleLogout)).Methods("POST")

	// Routes that require being logged in.
	p.router.HandleFunc(v1.PoliteiaAPIRoute+v1.RouteSecret,
		logging(p.isLoggedIn(p.handleSecret))).Methods("POST")

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
					tls.CurveP521,
					tls.X25519},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

					//	// Allow browsers crapy crypto
					//	tls.TLS_RSA_WITH_RC4_128_SHA,
					//	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					//	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					//	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					//	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					//	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					//	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					//	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
					//	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					//	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					//	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
					//	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					//	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					//	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					//	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					//	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					//	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					//	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					//	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					//	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					//	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					//	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					//	tls.TLS_FALLBACK_SCSV,
				},
			}
			srv := &http.Server{
				Addr: listen,
				//Handler:   csrfHandle(p.router),
				Handler:   p.router,
				TLSConfig: cfg,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler), 0),
			}
			_ = csrfHandle
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
