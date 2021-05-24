// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// isLoggedIn ensures that a user is logged in before calling the next
// function.
func (p *politeiawww) isLoggedIn(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%v isLoggedIn: %v %v %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		id, err := p.sessions.GetSessionUserID(w, r)
		if err != nil {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}

		// Check if user is authenticated
		if id == "" {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}

		f(w, r)
	}
}

// isAdmin returns true if the current session has admin privileges.
func (p *politeiawww) isAdmin(w http.ResponseWriter, r *http.Request) (bool, error) {
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		return false, err
	}

	return user.Admin, nil
}

// isLoggedInAsAdmin ensures that a user is logged in as an admin user
// before calling the next function.
func (p *politeiawww) isLoggedInAsAdmin(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%v isLoggedInAsAdmin: %v %v %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// Check if user is admin
		isAdmin, err := p.isAdmin(w, r)
		if err != nil {
			log.Errorf("isLoggedInAsAdmin: isAdmin %v", err)
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}
		if !isAdmin {
			log.Debugf("%v user is not an admin", http.StatusForbidden)
			util.RespondWithJSON(w, http.StatusForbidden, www.UserError{})
			return
		}

		f(w, r)
	}
}

// closeBodyMiddleware closes the request body.
func closeBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		r.Body.Close()
	})
}

// loggingMiddleware logs all incoming commands before calling the next
// function.
//
// NOTE: LOGGING WILL LOG PASSWORDS IF TRACING IS ENABLED.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trace incoming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v %v %v", util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware recovers from any panics by logging the panic and
// returning a 500 response.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defer the function so that it gets executed when the request
		// is being closed out, not when its being opened.
		defer func() {
			if err := recover(); err != nil {
				errorCode := time.Now().Unix()
				log.Criticalf("%v %v %v %v Internal error %v: %v",
					util.RemoteAddr(r), r.Method, r.URL, r.Proto, errorCode, err)

				log.Criticalf("Stacktrace (THIS IS AN ACTUAL PANIC): %s",
					debug.Stack())

				util.RespondWithJSON(w, http.StatusInternalServerError,
					www.ErrorReply{
						ErrorCode: errorCode,
					})
			}
		}()

		next.ServeHTTP(w, r)
	})
}
