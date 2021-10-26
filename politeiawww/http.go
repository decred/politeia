// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	"github.com/decred/politeia/politeiawww/logger"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// setupRoutes sets up the routes for the politeia http API.
func (p *politeiawww) setupRoutes() {
	/*
		// NOTE: This will override the legacy version route.
		// Disable it until we are ready to switch over.

		// The version routes set the CSRF header token and thus needs
		// to be part of the CSRF protected auth router so that the
		// cookie CSRF is set too. The CSRF cookie is set on all auth
		// routes. The header token is only set on the version route.
		addRoute(p.auth, http.MethodGet, "", "/", p.handleVersion)
		addRoute(p.auth, http.MethodGet, v1.APIRoute,
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
		BuildVersion: version.String(),
		Plugins:      append(p.authPlugins, p.standardPlugins...),
	}

	// Set the CSRF header. This is the only route
	// that sets the CSRF header.
	w.Header().Set(v1.CSRFTokenHeader, csrf.Token(r))

	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleWrite is the request handler for the http v1 Write command.
func (p *politeiawww) handleWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWrite")

	// Decode the request body
	var cmd v1.PluginCmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		respondWithError(w, r, "",
			v1.UserError{
				ErrorCode: v1.ErrorCodeInvalidInput,
			})
		return
	}

	// Verify plugin exists
	_, ok := p.plugins[cmd.PluginID]
	if !ok {
		respondWithError(w, r, "",
			v1.UserError{
				ErrorCode: v1.ErrorCodePluginNotFound,
			})
		return
	}

	// Get the session from the request cookie
	s, err := p.sessions.Get(r, v1.SessionCookieName)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: get session: %v", err)
		return
	}

	// Execute plugin command
	var (
		session = convertSession(*s)
		command = convertCmd(cmd)
	)
	reply, err := p.execWrite(r.Context(), cmd.PluginID, command, &session)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: execWrite: %v", err)
		return
	}

	// Save any updated session values
	s.Values = session.Values
	err = p.saveSession(r, w, s)
	if err != nil {
		// The database transaction for the plugin write has
		// already been committed and can't be rolled back.
		// Handled the error gracefully. Log it and continue.
		log.Errorf("handleWrite: saveSession %v: %v", s.ID, err)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// saveSession saves the encoded session values to the database and the encoded
// session ID to the response cookie. This is only performed if there are
// session values that need to be saved.
func (p *politeiawww) saveSession(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	if len(s.Values) == 0 {
		// Nothing to save
		return nil
	}
	return p.sessions.Save(r, w, s)
}

// addRoute adds a route to the provided router.
func addRoute(router *mux.Router, method string, routePrefix, route string, handler http.HandlerFunc) {
	router.HandleFunc(routePrefix+route, handler).Methods(method)
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

// responseWithError checks the error type and responds with the appropriate
// HTTP status body and response body.
func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	// Check if the client dropped the connection
	if err := r.Context().Err(); err == context.Canceled {
		log.Infof("%v %v %v %v client aborted connection",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// The client dropped the connection. There
		// is no need to send a response.
		return
	}

	// Check for expected error types
	var (
		ue v1.UserError
	)
	switch {
	case errors.As(err, &ue):
		// User error. Log it and return a 400.
		m := fmt.Sprintf("%v user error: %v %v", util.RemoteAddr(r),
			ue.ErrorCode, v1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			v1.UserError{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return

	default:
		// Internal server error. Log it and return a 500.
		t := time.Now().Unix()
		e := fmt.Sprintf(format, err)
		log.Errorf("%v %v %v %v Internal error %v: %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, e)

		// If this is a pkg/errors error then we can pull the
		// stack trace out of the error, otherwise, we use the
		// stack trace that points to this function.
		stack, ok := util.StackTrace(err)
		if !ok {
			stack = string(debug.Stack())
		}

		log.Errorf("Stacktrace (NOT A REAL CRASH): %v", stack)

		util.RespondWithJSON(w, http.StatusInternalServerError,
			v1.InternalError{
				ErrorCode: t,
			})
		return
	}
}

func convertCmd(c v1.PluginCmd) plugin.Cmd {
	return plugin.Cmd{
		Cmd:     c.Cmd,
		Payload: c.Payload,
	}
}

func convertSession(s sessions.Session) plugin.Session {
	return plugin.Session{
		Values: s.Values,
	}
}
