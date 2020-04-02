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

	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/util"
)

// isLoggedIn ensures that a user is logged in before calling the next
// function.
func (p *politeiawww) isLoggedIn(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("isLoggedIn: %v %v %v %v", remoteAddr(r), r.Method,
			r.URL, r.Proto)

		id, err := p.getSessionUserID(w, r)
		if err != nil {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.ErrorReply{
				ErrorCode: int64(www.ErrorStatusNotLoggedIn),
			})
			return
		}

		// Check if user is authenticated
		if id == "" {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.ErrorReply{
				ErrorCode: int64(www.ErrorStatusNotLoggedIn),
			})
			return
		}

		f(w, r)
	}
}

// isAdmin returns true if the current session has admin privileges.
func (p *politeiawww) isAdmin(w http.ResponseWriter, r *http.Request) (bool, error) {
	user, err := p.getSessionUser(w, r)
	if err != nil {
		return false, err
	}

	return user.Admin, nil
}

// isLoggedInAsAdmin ensures that a user is logged in as an admin user
// before calling the next function.
func (p *politeiawww) isLoggedInAsAdmin(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("isLoggedInAsAdmin: %v %v %v %v", remoteAddr(r),
			r.Method, r.URL, r.Proto)

		// Check if user is admin
		isAdmin, err := p.isAdmin(w, r)
		if err != nil {
			log.Errorf("isLoggedInAsAdmin: isAdmin %v", err)
			util.RespondWithJSON(w, http.StatusUnauthorized, www.ErrorReply{
				ErrorCode: int64(www.ErrorStatusNotLoggedIn),
			})
			return
		}
		if !isAdmin {
			util.RespondWithJSON(w, http.StatusForbidden, www.ErrorReply{})
			return
		}

		f(w, r)
	}
}

// logging logs all incoming commands before calling the next funxtion.
//
// NOTE: LOGGING WILL LOG PASSWORDS IF TRACING IS ENABLED.
func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		log.Infof("%v %v %v %v", remoteAddr(r), r.Method, r.URL, r.Proto)
		f(w, r)
	}
}

// closeBody closes the request body.
func closeBody(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		r.Body.Close()
	}
}

func remoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(www.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}

// recoverMiddleware recovers from any panics by logging the panic and
// returning a 500 response.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				errorCode := time.Now().Unix()
				log.Criticalf("%v %v %v %v Internal error %v: %v", remoteAddr(r),
					r.Method, r.URL, r.Proto, errorCode, err)
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
