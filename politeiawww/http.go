// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/mux"
)

/*
Add custom permission classes.
Set permissions on routes. Need to map classes to non-CSRF and CSRF routers.
Set permissions on users.
Routes check permissions.

Set permission on user creation.
Allow sysadmin to update user permission.
*/

// setupRoutes sets up the routes for the politeia http API.
func (p *politeiawww) setupRoutes() {
	/*
		// NOTE: these will override the legacy version routes.
		// Disable them until we are ready to switch over.
		addRoute(p.router, http.MethodGet, "",
			"/", p.handleVersion)
		addRoute(p.router, http.MethodGet, v1.APIRoute,
			v1.RouteVersion, p.handleVersion)
	*/

	addRoute(p.auth, http.MethodPost, v1.APIRoute,
		v1.RouteWrite, p.handleWrite)
}

// handleVersion is the request handler for the http v1 Version command.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	vr := v1.VersionReply{
		APIVersion:   v1.APIVersion,
		APIRoute:     v1.APIRoute,
		BuildVersion: version.String(),
		Plugins:      []string{},
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleWrite is the request handler for the http v1 Write command.
func (p *politeiawww) handleWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWrite")

	// Pre plugin hooks
	//  - Check cookie session
	//  - Check user permissions

	var wr *v1.WriteReply

	// Post plugin hooks

	util.RespondWithJSON(w, http.StatusOK, wr)
}

// addRoute adds a route to the provided router.
func addRoute(router *mux.Router, method string, routePrefix string, route string, handler http.HandlerFunc) {
	fullRoute := routePrefix + route
	router.HandleFunc(fullRoute, handler).Methods(method)
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
