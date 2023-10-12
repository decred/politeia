// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

func NewRouter(reqBodySizeLimit int64, csrfKey []byte, csrfMaxAge uint32) (*mux.Router, *mux.Router) {
	// Setup the public router
	public := mux.NewRouter()
	public.StrictSlash(true) // Ignore trailing slashes
	public.NotFoundHandler = http.HandlerFunc(handleNotFound)

	// Add router middleware. Middleware is executed
	// in the same order that they are registered in.
	m := middleware{
		reqBodySizeLimit: reqBodySizeLimit,
	}
	public.Use(closeBodyMiddleware) // MUST be registered first
	public.Use(m.reqBodySizeLimitMiddleware)
	public.Use(loggingMiddleware)
	public.Use(recoverMiddleware)

	// Setup a subrouter that is CSRF protected. Authenticated routes are
	// required to use the protected router. The subrouter takes on the
	// configuration of the router that it was spawned from, including all
	// of the middleware that has already been registered.
	protected := public.NewRoute().Subrouter()

	// The CSRF middleware uses the double submit cookie method. The server
	// provides clients with two CSRF tokens: a cookie token and a header
	// token. The cookie token is set automatically by the CSRF protected
	// subrouter anytime one of the protected routes it hit. The header token
	// must be set manually by a request handler. Clients MUST provide both
	// tokens in their request if they want to access a CSRF protected route.
	// The CSRF protected subrouter returns a 403 HTTP status code if a client
	// attempts to access a protected route without providing the proper CSRF
	// tokens.
	csrfMiddleware := csrf.Protect(
		csrfKey,
		// Set the CSRF cookie on all auth router paths and subpaths.
		csrf.Path("/"),
		csrf.MaxAge(int(csrfMaxAge)),
	)
	protected.Use(csrfMiddleware)

	return public, protected
}
