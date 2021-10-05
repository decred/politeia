// Copyright (c) 2017-2021 The Decred developers
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

// middleware contains the middleware that use configurable settings.
type middleware struct {
	reqBodySizeLimit int64 // In bytes
}

// reqBodySizeLimitMiddleware applies a maximum request body size limit to
// requests.
//
// NOTE: This will only cause an error if the request body is read by the
// request handler, e.g. the JSON from a POST request is decoded into a struct.
func (m *middleware) reqBodySizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("Applying a max body size of %v bytes to the request body",
			m.reqBodySizeLimit)

		r.Body = http.MaxBytesReader(w, r.Body, m.reqBodySizeLimit)
		next.ServeHTTP(w, r)
	})
}
