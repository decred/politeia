package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"syscall"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	// versionReply is the cached version reply.
	versionReply []byte
)

// User is a database record that persists user information.
type User struct {
	Id     uint
	Email  string
	Secret string
	Admin  bool
}

// politeiawww application context.
type politeiawww struct {
	cfg    *config
	router *mux.Router

	store *sessions.CookieStore
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

func (p *politeiawww) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Infof("login")
	session, _ := p.store.Get(r, v1.CookieSession)

	// Authenticate the request, get the id from the route params,
	// and fetch the user from the DB, etc.

	session.Values["authenticated"] = true
	session.Save(r, w)

	// Get the token and pass it in the CSRF header. Our JSON-speaking client
	// or JavaScript framework can now read the header and return the token in
	// in its own "X-CSRF-Token" request header on the subsequent POST.
	w.Header().Set(v1.CsrfToken, csrf.Token(r))
	user := User{Id: 10}
	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), 500) // XXX
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (p *politeiawww) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Infof("logout")
	session, _ := p.store.Get(r, v1.CookieSession)

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

func (p *politeiawww) handleSecret(w http.ResponseWriter, r *http.Request) {
	log.Infof("secret")
}

func (p *politeiawww) isLoggedIn(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("isLoggedIn: %v %v%v %v", r.Method, r.RemoteAddr,
			r.URL, r.Proto)
		session, err := p.store.Get(r, v1.CookieSession)
		if err != nil {
			log.Errorf("isLoggedIn: %v", err)
			http.Error(w, http.StatusText(http.StatusForbidden),
				http.StatusForbidden)
			return
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, http.StatusText(http.StatusForbidden),
				http.StatusForbidden)
			return
		}

		f(w, r)
	}
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trace incomming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v%v %v", r.Method, r.RemoteAddr, r.URL, r.Proto)
		f(w, r)
	}
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

	// We don't persist connections to generate a new key every time we
	// restart.
	csrfKey, err := util.Random(32)
	if err != nil {
		return err
	}
	csrfHandle := csrf.Protect(csrfKey)
	p.router = mux.NewRouter()
	p.router.HandleFunc("/", logging(p.handleVersion)).Methods("GET")
	p.router.HandleFunc(v1.PoliteiaAPIRoute+v1.RouteLogin,
		logging(p.handleLogin)).Methods("POST")
	p.router.HandleFunc(v1.PoliteiaAPIRoute+v1.RouteLogout,
		logging(p.handleLogout)).Methods("POST")
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
				CurvePreferences: []tls.CurveID{tls.CurveP521,
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
