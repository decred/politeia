// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"time"

	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/util"
)

const (
	// reqBodySizeLimit is the maximum number of bytes allowed in a request body.
	reqBodySizeLimit = 5 * 1024 * 1024 // 5 MiB
)

// closeBodyMiddleware closes the request body.
func closeBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		r.Body.Close()
	})
}

// maxBodySizeMiddleware applies a maximum size limit to the request body.
func maxBodySizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, reqBodySizeLimit)
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs all incoming commands before calling the next
// function.
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
					v2.ServerErrorReply{
						ErrorCode: errorCode,
					})
			}
		}()

		next.ServeHTTP(w, r)
	})
}
