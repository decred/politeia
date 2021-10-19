// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
)

func (p *politeiawww) addRoute(method string, routePrefix string, route string, handler http.HandlerFunc) {
	fullRoute := routePrefix + route

	// Add route to public router
	p.router.HandleFunc(fullRoute, handler).Methods(method)
}

// handleNotFound handles all invalid routes and returns a 404 to the client.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	// Log incoming connection
	log.Debugf("Invalid route: %v %v %v %v",
		util.RemoteAddr(r), r.Method, r.URL, r.Proto)

	// Trace incoming request
	log.Tracef("%v", logger.NewLogClosure(func() string {
		trace, err := httputil.DumpRequest(r, true)
		if err != nil {
			trace = []byte(fmt.Sprintf("handleNotFound: DumpRequest %v", err))
		}
		return string(trace)
	}))

	util.RespondWithJSON(w, http.StatusNotFound, nil)
}
