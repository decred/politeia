// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	"github.com/decred/politeia/util"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

const (
	csrfKeyLength    = 32    // In bytes
	csrfCookieMaxAge = 86400 // 1 day in seconds
)

// setupRouter sets up the router for the politeiawww http API.
func (p *politeiawww) setupRouter() error {
	// Setup the router
	p.router = mux.NewRouter()
	p.router.StrictSlash(true) // Ignore trailing slashes

	// Add a 404 handler
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// Add router middleware. Middleware is executed
	// in the same order that they are registered in.
	m := middleware{
		reqBodySizeLimit: p.cfg.ReqBodySizeLimit,
	}
	p.router.Use(closeBodyMiddleware) // MUST be registered first
	p.router.Use(m.reqBodySizeLimitMiddleware)
	p.router.Use(loggingMiddleware)
	p.router.Use(recoverMiddleware)

	// Setup a subrouter that is CSRF protected. Authenticated routes are
	// required to use the protected router. The subrouter takes on the
	// configuration of the router that it was spawned from, including all
	// of the middleware that has already been registered.
	p.protected = p.router.NewRoute().Subrouter()

	// The CSRF middleware uses the double submit cookie method. The server
	// provides clients with two CSRF tokens: a cookie token and a header
	// token. The cookie token is set automatically by the CSRF protected
	// subrouter anytime one of the protected routes it hit. The header token
	// must be set manually by a request handler. Clients MUST provide both
	// tokens in their request if they want to access a CSRF protected route.
	// The CSRF protected subrouter returns a 403 HTTP status code if a client
	// attempts to access a protected route without providing the proper CSRF
	// tokens.
	csrfKey, err := p.loadCSRFKey()
	if err != nil {
		return err
	}
	csrfMiddleware := csrf.Protect(
		csrfKey,
		// Set the CSRF cookie on all auth router paths and subpaths.
		csrf.Path("/"),
		csrf.MaxAge(csrfCookieMaxAge),
	)
	p.protected.Use(csrfMiddleware)

	return nil
}

// setupRoutes set ups the http/v3 API routes.
func (p *politeiawww) setupRoutes() {
	// NOTE: This will override the legacy version route.
	// Disable it until we are ready to switch over.
	// addRoute(p.protected, http.MethodGet, "", "/", p.handleVersion)

	// The version routes set the CSRF header token and thus needs
	// to be part of the CSRF protected auth router so that the
	// cookie CSRF is set too. The CSRF cookie is set on all auth
	// routes. The header token is only set on the version route.
	addRoute(p.protected, http.MethodGet, v3.APIVersionPrefix,
		v3.VersionRoute, p.handleVersion)

	// Unprotected routes
	addRoute(p.router, http.MethodGet, v3.APIVersionPrefix,
		v3.PolicyRoute, p.handlePolicy)
	addRoute(p.router, http.MethodPost, v3.APIVersionPrefix,
		v3.ReadRoute, p.handleRead)
	// addRoute(p.router, http.MethodPost, v3.APIVersionPrefix,
	//	v3.ReadBatchRoute, p.handleReadBatch)

	// CSRF protected routes
	addRoute(p.protected, http.MethodPost, v3.APIVersionPrefix,
		v3.WriteRoute, p.handleWrite)
}

// addRoute adds a route to the provided router.
func addRoute(router *mux.Router, method string, routePrefix, route string, handler http.HandlerFunc) {
	router.HandleFunc(routePrefix+route, handler).Methods(method)
}

// loadCSRFKey loads the CSRF key from disk. If a CSRF key does not exist then
// one is created and saved to disk for future use.
func (p *politeiawww) loadCSRFKey() ([]byte, error) {
	log.Infof("Load CSRF key")

	// Open the CSRF key file
	fp := filepath.Join(p.cfg.DataDir, "csrf.key")
	fCSRF, err := os.Open(fp)
	switch {
	case err == nil:
		// CSRF key exists; continue

	case os.IsNotExist(err):
		// CSRF key does not exist. Create one
		// and save it to disk.
		key, err := util.Random(csrfKeyLength)
		if err != nil {
			return nil, err
		}

		fCSRF, err = os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		_, err = fCSRF.Write(key)
		if err != nil {
			return nil, err
		}
		_, err = fCSRF.Seek(0, 0)
		if err != nil {
			return nil, err
		}

		log.Infof("CSRF key created and saved to %v", fp)

	default:
		// All other errors
		return nil, err
	}

	// Read the CSRF key from the file
	csrfKey := make([]byte, csrfKeyLength)
	r, err := fCSRF.Read(csrfKey)
	if err != nil {
		return nil, err
	}
	fCSRF.Close()

	if r != csrfKeyLength {
		return nil, fmt.Errorf("CSRF key corrupt")
	}

	return csrfKey, nil
}
