// Copyright (c) 2017-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/decred/politeia/app"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// politeiawww represents the politeiawww server.
type politeiawww struct {
	cfg       *config.Config
	router    *mux.Router // Public router
	protected *mux.Router // CSRF protected subrouter
	sessions  sessions.Store
	app       app.App

	// cmds contains all valid plugin commands for the app.
	//
	// This allows politeia to validate incoming plugin command requests without
	// having to query the app. This map is built on startup and is static.
	//
	// The map key is the "pluginID-version-cmdName".
	cmds map[string]struct{}

	// legacy contains the legacy politeiawww server.
	legacy *legacy.Politeiawww
}

func _main() error {
	// Load the configuration and parse the command line. This
	// also initializes logging and configures it accordingly.
	cfg, _, err := config.Load()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		logger.CloseLogRotator()
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Network : %v", cfg.ActiveNet.Name)
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
	if !util.FileExists(cfg.HTTPSKey) &&
		!util.FileExists(cfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			cfg.HTTPSCert, cfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created")
	}

	// Setup the politeiad client
	pdc, err := pdclient.New(cfg.RPCHost, cfg.RPCCert,
		cfg.RPCUser, cfg.RPCPass, cfg.Identity)
	if err != nil {
		return err
	}

	// Connect to the database
	var (
		connMaxLifetime = 0 * time.Minute // 0 is unlimited
		maxOpenConns    = 0               // 0 is unlimited
		maxIdleConns    = 10

		// TODO hardcoding bad
		user     = "politeiawww"
		password = cfg.DBPass
		host     = cfg.DBHost
		dbname   = "proposals_testnet3"
	)

	log.Infof("MySQL host: %v:[password]@tcp(%v)/%v", user, host, dbname)

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", user, password, host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return err
	}

	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	err = db.Ping()
	if err != nil {
		return err
	}

	// Setup application context
	p := &politeiawww{
		cfg:       cfg,
		router:    nil, // Set in setupRouter
		protected: nil, // Set in setupRouter
		sessions:  nil, // Set in setupSessions
		app:       nil, // Set in setupApp
		cmds:      make(map[string]struct{}),

		// Legacy fields
		legacy: nil, // Set below
	}
	err = p.setupRouter()
	if err != nil {
		return err
	}

	// Setup the API routes. The legacy routes are setup
	// by default, unless an app has been specified in
	// the config.
	switch {
	case cfg.App != "":
		// Run in app mode
		p.setupRoutes()
		err = p.setupSessions(db)
		if err != nil {
			return err
		}

		log.Infof("Running app: %v", cfg.App)

		err = p.setupApp()
		if err != nil {
			return err
		}

	default:
		// Run in legacy mode
		log.Infof("Running in legacy mode")
		legacywww, err := legacy.NewPoliteiawww(p.cfg,
			p.router, p.protected, cfg.ActiveNet.Params,
			pdc)
		if err != nil {
			return err
		}
		p.legacy = legacywww
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

	if p.legacy != nil {
		p.legacy.Close()
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
