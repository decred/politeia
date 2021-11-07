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
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
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
		addRoute(p.protected, http.MethodGet, "", "/", p.handleVersion)
		addRoute(p.protected, http.MethodGet, v1.APIRoute,
		  v1.VersionRoute, p.handleVersion)
	*/

	addRoute(p.protected, http.MethodPost, v1.APIRoute,
		v1.WriteRoute, p.handleWrite)
}

// handleVersion is the request handler for the http v1 VersionRoute.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	plugins := make(map[string]uint32, len(p.plugins))
	for _, plugin := range p.plugins {
		plugins[plugin.ID()] = plugin.Version()
	}

	vr := v1.VersionReply{
		APIVersion:   v1.APIVersion,
		BuildVersion: version.String(),
		Plugins:      plugins,
	}

	// Set the CSRF header. This is the only route
	// that sets the CSRF header.
	w.Header().Set(v1.CSRFTokenHeader, csrf.Token(r))

	util.RespondWithJSON(w, http.StatusOK, vr)
}

// handleWrite is the request handler for the http v1 WriteRoute.
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
	s, err := p.extractSession(r)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: extractSession: %v", err)
		return
	}

	// Execute the plugin command
	var (
		pluginID      = cmd.PluginID
		pluginSession = convertSession(s)
		pluginCmd     = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execWrite(r.Context(),
		pluginSession, pluginID, pluginCmd)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: execWrite: %v", err)
		return
	}

	reply := convertReplyToHTTP(cmd.PluginID, cmd.Cmd, *pluginReply)

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed.
		// Handled the error gracefully. Log it and continue.
		log.Errorf("handleWrite: saveSession: %v", err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleRead is the request handler for the http v1 ReadRoute.
func (p *politeiawww) handleRead(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRead")

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
	s, err := p.extractSession(r)
	if err != nil {
		respondWithError(w, r,
			"handleRead: extractSession: %v", err)
		return
	}

	// Execute the plugin command
	var (
		pluginID      = cmd.PluginID
		pluginSession = convertSession(s)
		pluginCmd     = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execRead(r.Context(),
		pluginSession, pluginID, pluginCmd)
	if err != nil {
		respondWithError(w, r,
			"handleRead: execRead: %v", err)
		return
	}

	reply := convertReplyToHTTP(cmd.PluginID, cmd.Cmd, *pluginReply)

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed. Handle
		// the error gracefully. Log it and continue.
		log.Errorf("handleRead: saveSession: %v", err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleReadBatch is the request handler for the http v1 ReadBatchRoute.
func (p *politeiawww) handleReadBatch(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleReadBatch")

	// Decode the request body
	var batch v1.Batch
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&batch); err != nil {
		util.RespondWithJSON(w, http.StatusOK,
			v1.PluginReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodeInvalidInput,
				},
			})
		return
	}

	// Extract the session data from the request cookies
	s, err := p.extractSession(r)
	if err != nil {
		respondWithError(w, r,
			"handleReadBatch: extractSession: %v", err)
		return
	}

	var (
		pluginSession = convertSession(s)
		replies       = make([]v1.PluginReply, len(batch.Cmds))
	)
	for i, cmd := range batch.Cmds {
		// Verify plugin exists
		_, ok := p.plugins[cmd.PluginID]
		if !ok {
			replies[i] = v1.PluginReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodePluginNotFound,
				},
			}
			continue
		}

		// Execute the plugin command
		pluginReply, err := p.execRead(r.Context(), pluginSession,
			cmd.PluginID, convertCmdFromHTTP(cmd))
		if err != nil {
			respondWithError(w, r,
				"handleReadBatch: execRead: %v", err)
			return
		}

		replies[i] = convertReplyToHTTP(cmd.PluginID, cmd.Cmd, *pluginReply)
	}

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed. Handle
		// the error gracefully. Log it and continue.
		log.Errorf("handleReadBatch: saveSession: %v", err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK,
		v1.BatchReply{
			Replies: replies,
		})
}

// responseWithError checks the error type and responds with the appropriate
// HTTP error response.
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
