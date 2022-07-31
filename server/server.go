// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/server/api/v1"
	sn "github.com/decred/politeia/server/sessions"
	sndb "github.com/decred/politeia/server/sessions/mysql"
	"github.com/decred/politeia/util"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

// Server is the politeia server.
type Server struct {
	cfg       *Config
	server    *http.Server
	router    *mux.Router // Parent router
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
}

func New(cfg *Config, db *sql.DB, a app.App) (*Server, error) {
	err := verifyConfig(cfg)
	if err != nil {
		return nil, err
	}
	err = generateHTTPSCertPair(cfg.HTTPSCert, cfg.HTTPSKey)
	if err != nil {
		return nil, err
	}
	csrfKey, err := loadCSRFKey(cfg.CSRFKey)
	if err != nil {
		return nil, err
	}
	sessionKey, err := loadSessionKey(cfg.SessionKey)
	if err != nil {
		return nil, err
	}

	// Setup the router
	csrfMaxAge := int(cfg.CSRFMaxAge)
	router, protected := NewRouter(cfg.ReqBodySizeLimit, csrfKey, csrfMaxAge)

	// Setup the sessions store
	sdb, err := sndb.New(db, cfg.SessionMaxAge, nil)
	if err != nil {
		return nil, err
	}
	opts := sn.NewOptions(int(cfg.SessionMaxAge))
	ss := sn.NewStore(sdb, opts, sessionKey)

	// Setup the server
	s := Server{
		cfg:       cfg,
		router:    router,
		protected: protected,
		sessions:  ss,
		app:       a,
		cmds:      make(map[string]struct{}),
	}

	s.setupRoutes()

	// Build the server's internal list of plugin commands
	for _, cmd := range s.app.Cmds() {
		s.cmds[cmd.String()] = struct{}{}
	}

	return &s, nil
}

func (s *Server) ListenAndServeTLS(listenC chan error) {
	go func() {
		s.server = &http.Server{
			Handler:      s.router,
			Addr:         s.cfg.Listen,
			ReadTimeout:  time.Duration(s.cfg.ReadTimeout) * time.Second,
			WriteTimeout: time.Duration(s.cfg.WriteTimeout) * time.Second,
			TLSConfig: &tls.Config{
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
			},
			TLSNextProto: make(map[string]func(*http.Server,
				*tls.Conn, http.Handler)),
		}
		log.Infof("Listen: %v", s.cfg.Listen)
		listenC <- s.server.ListenAndServeTLS(s.cfg.HTTPSCert, s.cfg.HTTPSKey)
	}()
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections.
func (s *Server) Shutdown() {
	err := s.server.Shutdown(context.Background())
	if err != nil {
		log.Errorf("Shutdown: %v", err)
	}
}

// setupRoutes set ups the v1 API routes.
func (s *Server) setupRoutes() {
	// NOTE: This will override the legacy version route.
	// Disable it until we are ready to switch over.
	// addRoute(s.protected, http.MethodGet, "", "/", s.handleVersion)

	// The version routes set the CSRF header token and thus needs
	// to be part of the CSRF protected auth router so that the
	// cookie CSRF is set too. The CSRF cookie is set on all auth
	// routes. The header token is only set on the version route.
	addRoute(s.protected, http.MethodGet, v1.APIVersionPrefix,
		v1.VersionRoute, s.handleVersion)

	// Unprotected routes
	addRoute(s.router, http.MethodGet, v1.APIVersionPrefix,
		v1.PolicyRoute, s.handlePolicy)
	addRoute(s.router, http.MethodPost, v1.APIVersionPrefix,
		v1.ReadRoute, s.handleRead)
	// addRoute(s.router, http.MethodPost, v1.APIVersionPrefix,
	//	v1.ReadBatchRoute, s.handleReadBatch)

	// CSRF protected routes
	addRoute(s.protected, http.MethodPost, v1.APIVersionPrefix,
		v1.WriteRoute, s.handleWrite)
}

// addRoute adds a route to the provided router.
func addRoute(router *mux.Router, method string, routePrefix, route string, handler http.HandlerFunc) {
	router.HandleFunc(routePrefix+route, handler).Methods(method)
}

// generateHTTPSCertPair generates an HTTPS cert and key if they don't already
// exist.
func generateHTTPSCertPair(httpsCert, httpsKey string) error {
	switch {
	case util.FileExists(httpsCert) && util.FileExists(httpsKey):
		// The cert and key already exist. Nothing to do.
		return nil

	case !util.FileExists(httpsCert) && util.FileExists(httpsKey):
		// The key exists, but the cert doesn't exist
		return fmt.Errorf("https key exists (%v) but the cert doesn't (%v)",
			httpsKey, httpsCert)

	case util.FileExists(httpsCert) && !util.FileExists(httpsKey):
		// The cert exists, but the key doesn't exist
		return fmt.Errorf("https cert exists (%v) but the key doesn't (%v)",
			httpsCert, httpsKey)
	}

	// A HTTPS cert pair does not exist. Generate one.
	err := util.GenCertPair(elliptic.P256(), "politeia", httpsCert, httpsKey)
	if err != nil {
		return fmt.Errorf("gen cert pair failed: %v", err)
	}

	return nil
}

// loadCSRFKey loads the CSRF key from disk. If a CSRF key does not exist, a
// new one is created and saved to disk.
func loadCSRFKey(csrfKeyFile string) ([]byte, error) {
	var csrfKeyLength = 32 // In bytes

	csrfKey, err := os.ReadFile(csrfKeyFile)
	if err != nil {
		log.Infof("CSRF key not found; generating one")
		csrfKey, err = util.Random(csrfKeyLength)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(csrfKeyFile, csrfKey, 0400)
		if err != nil {
			return nil, err
		}
		log.Infof("CSRF key saved to %v", csrfKeyFile)
	}

	if len(csrfKey) != csrfKeyLength {
		return nil, errors.Errorf("csrf key is corrupt")
	}

	return csrfKey, nil
}

// loadSessionKey loads the session key from disk. If a session key does not
// exist, a new one is created and saved to disk.
func loadSessionKey(sessionKeyFile string) ([]byte, error) {
	const sessionKeyLength = 32 // In bytes

	sessionKey, err := os.ReadFile(sessionKeyFile)
	if err != nil {
		log.Infof("Session key not found; generating one")
		sessionKey, err = util.Random(sessionKeyLength)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(sessionKeyFile, sessionKey, 0400)
		if err != nil {
			return nil, err
		}
		log.Infof("Session key saved to %v", sessionKeyFile)
	}

	if len(sessionKey) != sessionKeyLength {
		return nil, errors.Errorf("session key is corrupt")
	}

	return sessionKey, nil
}
