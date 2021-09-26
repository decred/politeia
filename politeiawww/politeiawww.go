// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"io/ioutil"
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
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/politeiawww/user/mysql"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

// politeiawww represents the politeiawww server.
type politeiawww struct {
	sync.RWMutex
	cfg       *config.Config
	params    *chaincfg.Params
	router    *mux.Router
	auth      *mux.Router // CSRF protected subrouter
	politeiad *pdclient.Client
	mail      mail.Mailer
	sessions  *sessions.Sessions
	events    *events.Manager

	// Client websocket connections
	ws    map[string]map[string]*wsContext // [uuid][]*context
	wsMtx sync.RWMutex
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
	log.Infof("Build Version: %v", version.BuildMainVersion())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Check if this command is being run to fetch the politeiad
	// identity.
	if loadedCfg.FetchIdentity {
		return getIdentity(loadedCfg.RPCHost, loadedCfg.RPCCert,
			loadedCfg.RPCIdentityFile, loadedCfg.Interactive)
	}

	// Generate the TLS cert and key file if both don't already exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created")
	}

	// Load or create new CSRF key
	log.Infof("Load CSRF key")
	csrfKeyFilename := filepath.Join(loadedCfg.DataDir, "csrf.key")
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
		reqBodySizeLimit: loadedCfg.ReqBodySizeLimit,
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
	pdc, err := pdclient.New(loadedCfg.RPCHost, loadedCfg.RPCCert,
		loadedCfg.RPCUser, loadedCfg.RPCPass, loadedCfg.Identity)
	if err != nil {
		return err
	}

	// Setup user database
	log.Infof("User database: %v", loadedCfg.UserDB)

	var userDB user.Database
	var mailerDB user.MailerDB
	switch loadedCfg.UserDB {
	case userDBLevel:
		db, err := localdb.New(loadedCfg.DataDir)
		if err != nil {
			return err
		}
		userDB = db

	case userDBMySQL, userDBCockroach:
		// If old encryption key is set it means that we need
		// to open a db connection using the old key and then
		// rotate keys.
		var encryptionKey string
		if loadedCfg.OldEncryptionKey != "" {
			encryptionKey = loadedCfg.OldEncryptionKey
		} else {
			encryptionKey = loadedCfg.EncryptionKey
		}

		// Open db connection.
		network := filepath.Base(loadedCfg.DataDir)
		switch loadedCfg.UserDB {
		case userDBMySQL:
			mysql, err := mysql.New(loadedCfg.DBHost,
				loadedCfg.DBPass, network, encryptionKey)
			if err != nil {
				return fmt.Errorf("new mysql db: %v", err)
			}
			userDB = mysql
			mailerDB = mysql
		case userDBCockroach:
			cdb, err := cockroachdb.New(loadedCfg.DBHost, network,
				loadedCfg.DBRootCert, loadedCfg.DBCert, loadedCfg.DBKey,
				encryptionKey)
			if err != nil {
				return fmt.Errorf("new cdb db: %v", err)
			}
			userDB = cdb
			mailerDB = cdb
		}

		// Rotate keys.
		if loadedCfg.OldEncryptionKey != "" {
			err = userDB.RotateKeys(loadedCfg.EncryptionKey)
			if err != nil {
				return fmt.Errorf("rotate userdb keys: %v", err)
			}
		}

	default:
		return fmt.Errorf("invalid userdb '%v'", loadedCfg.UserDB)
	}

	// Setup sessions store
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(loadedCfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(loadedCfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return err
		}
		log.Infof("Cookie key generated")
	}

	// Setup politeiad client
	httpClient, err := util.NewHTTPClient(false, loadedCfg.RPCCert)
	if err != nil {
		return err
	}

	// Setup mailer smtp client
	mailer, err := mail.NewClient(loadedCfg.MailHost, loadedCfg.MailUser,
		loadedCfg.MailPass, loadedCfg.MailAddress, loadedCfg.MailCert,
		loadedCfg.MailSkipVerify, loadedCfg.MailRateLimit, mailerDB)
	if err != nil {
		return fmt.Errorf("new mail client: %v", err)
	}

	// Setup application context
	p := &politeiawww{
		cfg:        loadedCfg,
		params:     activeNetParams.Params,
		router:     router,
		auth:       auth,
		politeiad:  pdc,
		http:       httpClient,
		db:         userDB,
		mail:       mailer,
		sessions:   sessions.New(userDB, cookieKey),
		events:     events.NewManager(),
		ws:         make(map[string]map[string]*wsContext),
		userEmails: make(map[string]uuid.UUID),
	}

	// Setup email-userID cache
	err = p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Perform application specific setup
	switch p.cfg.Mode {
	case config.PoliteiaWWWMode:
		err = p.setupPi()
		if err != nil {
			return fmt.Errorf("setupPi: %v", err)
		}
	case config.CMSWWWMode:
		err = p.setupCMS()
		if err != nil {
			return fmt.Errorf("setupCMS: %v", err)
		}
	default:
		return fmt.Errorf("unknown mode: %v", p.cfg.Mode)
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
				Handler:      p.router,
				Addr:         listen,
				ReadTimeout:  time.Duration(loadedCfg.ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(loadedCfg.WriteTimeout) * time.Second,
				TLSConfig:    cfg,
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

	// Close user db connection
	p.db.Close()

	// Perform application specific shutdown
	switch p.cfg.Mode {
	case config.PoliteiaWWWMode:
		// Nothing to do
	case config.CMSWWWMode:
		p.wsDcrdata.Close()
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
