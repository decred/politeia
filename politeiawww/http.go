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
)

/*
Add custom permission classes.
Set permissions on routes.
Set permissions on users.
Routes check permissions.

Need a permissions user plugin.
Set permission on user creation.
Update permission.
*/

func (p *politeiawww) setupRoutes() {
	// NOTE: these will override the legacy version routes.
	// Disable them until we are ready to switch over.
	// p.addRoute(http.MethodGet, "",
	//		"/", p.handleVersion)
	// p.addRoute(http.MethodGet, v1.APIRoute,
	// 	 v1.RouteVersion, p.handleVersion)

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
