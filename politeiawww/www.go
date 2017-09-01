package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/decred/dcrtime/util"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

const (
	politeiaAPIVersion = 1 // API version this backend understands

	csrfToken = "X-CSRF-Token" // CSRF token for replies
)

var (
	// politeiaAPIRoute is the prefix to the API route
	politeiaAPIRoute = fmt.Sprintf("api/v%v", politeiaAPIVersion)

	// versionReply is the cached version reply.
	versionReply []byte
)

// Version command is used to determine the version of the API this backend
// understands and additionally it provides the route to said API.
type Version struct {
	Version uint   // politeia WWW API version
	Route   string // prefix to API calls
}

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
}

// init sets default values at startup.
func init() {
	var err error
	versionReply, err = json.Marshal(Version{
		Version: politeiaAPIVersion,
		Route:   politeiaAPIRoute,
	})
	if err != nil {
		panic(fmt.Sprintf("versionReply: %v", err))
	}
}

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(csrfToken, csrf.Token(r))
	w.WriteHeader(http.StatusOK)
	w.Write(versionReply)
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request, get the id from the route params,
	// and fetch the user from the DB, etc.

	// Get the token and pass it in the CSRF header. Our JSON-speaking client
	// or JavaScript framework can now read the header and return the token in
	// in its own "X-CSRF-Token" request header on the subsequent POST.
	fmt.Printf("token: %v\n", csrf.Token(r))
	w.Header().Set(csrfToken, csrf.Token(r))
	user := User{Id: 10}
	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
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

	p.router = mux.NewRouter()
	p.router.HandleFunc("/", handleVersion).Methods("GET")
	//fmt.Printf("listening:\n")
	//http.ListenAndServe(":8000", csrf.Protect([]byte("32-byte-long-auth-key"),
	//	csrf.HttpOnly(false), csrf.Secure(false))(r))

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				p.router)
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
