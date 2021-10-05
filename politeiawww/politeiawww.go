// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/legacy"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

const (
	csrfKeyLength = 32
)

// politeiawww represents the politeiawww server.
type politeiawww struct {
	sync.RWMutex
	cfg       *config.Config
	params    *chaincfg.Params
	router    *mux.Router
	auth      *mux.Router // CSRF protected subrouter
	politeiad *pdclient.Client
	sessions  *sessions.Sessions
	events    *events.Manager
	legacy    *legacy.Politeiawww // Legacy API

	// Client websocket connections. These do not allow for horizontal scaling
	// yet.
	ws    map[string]map[string]*wsContext // [uuid][]*context
	wsMtx sync.RWMutex
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	cfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		logger.CloseLogRotator()
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", cfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Check if this command is being run to fetch the politeiad
	// identity.
	if cfg.FetchIdentity {
		return getIdentity(cfg.RPCHost, cfg.RPCCert,
			cfg.RPCIdentityFile, cfg.Interactive)
	}

	// Generate the TLS cert and key file if both don't already exist.
	if !fileExists(cfg.HTTPSKey) &&
		!fileExists(cfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			cfg.HTTPSCert, cfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created")
	}

	// Load or create new CSRF key
	log.Infof("Load CSRF key")
	csrfKeyFilename := filepath.Join(cfg.DataDir, "csrf.key")
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

	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Path("/"),
		csrf.MaxAge(sessions.SessionMaxAge),
	)

	// Setup the router. Middleware is executed in
	// the same order that they are registered in.
	router := mux.NewRouter()
	m := middleware{
		reqBodySizeLimit: cfg.ReqBodySizeLimit,
	}
	router.Use(closeBodyMiddleware) // MUST be registered first
	router.Use(m.reqBodySizeLimitMiddleware)
	router.Use(loggingMiddleware)
	router.Use(recoverMiddleware)

	// Setup 404 handler
	router.NotFoundHandler = http.HandlerFunc(handleNotFound)

	// Setup a subrouter that is CSRF protected. Authenticated routes
	// are required to use the auth router. The subrouter takes on the
	// configuration of the router that it was spawned from, including
	// all of the middleware that has already been registered.
	auth := router.NewRoute().Subrouter()
	auth.Use(csrfMiddleware)

	// Setup the politeiad client
	pdc, err := pdclient.New(cfg.RPCHost, cfg.RPCCert,
		cfg.RPCUser, cfg.RPCPass, cfg.Identity)
	if err != nil {
		return err
	}

	// Setup the legacy politeiawww context
	legacywww, err := legacy.NewPoliteiawww(cfg, router, auth,
		activeNetParams.Params, pdc)
	if err != nil {
		return err
	}

	// Setup application context
	p := &politeiawww{
		cfg:       cfg,
		params:    activeNetParams.Params,
		router:    router,
		auth:      auth,
		politeiad: pdc,
		// NOTE: This needs an implementation that
		// doesn't use the legacy user database.
		// sessions:   sessions.New(userDB, cookieKey),
		events: events.NewManager(),
		legacy: legacywww,
		ws:     make(map[string]map[string]*wsContext),
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range cfg.Listeners {
		listen := listener
		go func() {
			tlsConfig := &tls.Config{
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
				Handler:      p.router,
				Addr:         listen,
				ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
				TLSConfig:    tlsConfig,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler)),
			}

			log.Infof("Listen: %v", listen)
			listenC <- srv.ListenAndServeTLS(cfg.HTTPSCert,
				cfg.HTTPSKey)
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

	p.legacy.Close()

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
