// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	"github.com/decred/politeia/politeiawww/logger"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/politeiawww/user"
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
		util.RespondWithJSON(w, http.StatusOK,
			v1.PluginReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodeInvalidInput,
				},
			})
		return
	}

	// Verify plugin exists
	_, ok := p.plugins[cmd.PluginID]
	if !ok {
		util.RespondWithJSON(w, http.StatusOK,
			v1.PluginReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodePluginNotFound,
				},
			})
		return
	}

	// Extract the session data from the request cookies
	s, u, err := p.extractSession(r)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: extractSession: %v", err)
		return
	}

	// Execute the plugin command
	var (
		// session = convertSession(*s)
		pluginID = cmd.PluginID
		usr      = convertUser(u, s, cmd.PluginID)
		command  = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execWrite(r.Context(), pluginID, command, usr)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: execWrite: %v", err)
		return
	}

	reply := convertReplyToHTTP(pluginID, cmd.Cmd, *pluginReply)

	// Save the updated session
	err = p.saveUserSession(r, w, s, usr, pluginID)
	if err != nil {
		// The database transaction for the plugin write has
		// already been committed and can't be rolled back.
		// Handled the error gracefully. Log it and continue.
		log.Errorf("handleWrite: saveSession %v: %v", s.ID, err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK, reply)
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

func convertCmdFromHTTP(c v1.PluginCmd) plugin.Cmd {
	return plugin.Cmd{
		Cmd:     c.Cmd,
		Payload: c.Payload,
	}
}

func convertReplyToHTTP(pluginID, cmd string, r plugin.Reply) v1.PluginReply {
	return v1.PluginReply{
		PluginID: pluginID,
		Cmd:      cmd,
		Payload:  r.Payload,
		Error:    r.Error,
	}
}

func convertUser(u *user.User, s *sessions.Session, pluginID string) *plugin.User {
	// Get the user data and session value for the plugin.
	var (
		data  = u.Plugins[pluginID]
		value = s.Values[pluginID]
	)

	// The session value is a interface{}. Convert it to a string.
	var sessionValue string
	if value != nil {
		sessionValue = value.(string)
	}

	return &plugin.User{
		ID:         u.ID,
		Session:    plugin.NewSession(sessionValue),
		PluginData: plugin.NewPluginData(data.ClearText, data.Encrypted),
	}
}
