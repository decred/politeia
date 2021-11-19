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
	"strings"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/http/v1"
	"github.com/decred/politeia/politeiawww/logger"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
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

	// Unprotected routes
	addRoute(p.router, http.MethodGet, v1.APIRoute,
		v1.PolicyRoute, p.handlePolicy)
	addRoute(p.router, http.MethodPost, v1.APIRoute,
		v1.ReadRoute, p.handleRead)
	addRoute(p.router, http.MethodPost, v1.APIRoute,
		v1.ReadBatchRoute, p.handleReadBatch)

	// CSRF protected routes
	addRoute(p.protected, http.MethodPost, v1.APIRoute,
		v1.NewUserRoute, p.handleNewUser)
	addRoute(p.protected, http.MethodPost, v1.APIRoute,
		v1.WriteRoute, p.handleWrite)
}

// handleVersion is the request handler for the http v1 VersionRoute.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	// Set the CSRF header. This is the only route
	// that sets the CSRF header.
	w.Header().Set(v1.CSRFTokenHeader, csrf.Token(r))

	plugins := make(map[string]uint32, len(p.plugins))
	for _, plugin := range p.plugins {
		plugins[plugin.ID()] = plugin.Version()
	}

	util.RespondWithJSON(w, http.StatusOK,
		v1.VersionReply{
			APIVersion:   v1.APIVersion,
			BuildVersion: version.String(),
			Plugins:      plugins,
		})
}

// handlePolicy is the request handler for the http v1 PolicyRoute.
func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePolicy")

	util.RespondWithJSON(w, http.StatusOK,
		v1.PolicyReply{
			ReadBatchLimit: p.cfg.PluginBatchLimit,
		})
}

// handleNewUser is the request handler for the http v1 NewUserRoute.
func (p *politeiawww) handleNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewUser")

	// Decode the request body
	var cmd v1.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		util.RespondWithJSON(w, http.StatusOK,
			v1.CmdReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodeInvalidInput,
				},
			})
		return
	}

	// Verify the plugin is the user plugin
	if p.userPlugin.ID() != cmd.PluginID {
		util.RespondWithJSON(w, http.StatusOK,
			v1.CmdReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodePluginNotAuthorized,
				},
			})
		return
	}

	// Extract the session data from the request cookies
	s, err := p.extractSession(r)
	if err != nil {
		respondWithError(w, r,
			"handleNewUser: extractSession: %v", err)
		return
	}

	// Execute the plugin command
	var (
		pluginSession = convertSession(s)
		pluginCmd     = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execNewUser(r.Context(), pluginSession, pluginCmd)
	if err != nil {
		respondWithError(w, r,
			"handleNewUser: execNewUser: %v", err)
		return
	}

	reply := convertReplyToHTTP(pluginCmd, *pluginReply)

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed.
		// Handled the error gracefully.
		log.Errorf("handleNewUser: saveSession: %v", err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleWrite is the request handler for the http v1 WriteRoute.
func (p *politeiawww) handleWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWrite")

	// Decode the request body
	var cmd v1.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		util.RespondWithJSON(w, http.StatusOK,
			v1.CmdReply{
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
			v1.CmdReply{
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
		pluginSession = convertSession(s)
		pluginCmd     = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execWrite(r.Context(), pluginSession, pluginCmd)
	if err != nil {
		respondWithError(w, r,
			"handleWrite: execWrite: %v", err)
		return
	}

	reply := convertReplyToHTTP(pluginCmd, *pluginReply)

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed.
		// Handled the error gracefully.
		log.Errorf("handleWrite: saveSession: %v", err)
	}

	// Send the response
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleRead is the request handler for the http v1 ReadRoute.
func (p *politeiawww) handleRead(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRead")

	// Decode the request body
	var cmd v1.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		util.RespondWithJSON(w, http.StatusOK,
			v1.CmdReply{
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
			v1.CmdReply{
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
		pluginSession = convertSession(s)
		pluginCmd     = convertCmdFromHTTP(cmd)
	)
	pluginReply, err := p.execRead(r.Context(), pluginSession, pluginCmd)
	if err != nil {
		respondWithError(w, r,
			"handleRead: execRead: %v", err)
		return
	}

	reply := convertReplyToHTTP(pluginCmd, *pluginReply)

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed.
		// Handle the error gracefully.
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
			v1.CmdReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodeInvalidInput,
				},
			})
		return
	}
	cmds, err := decodeCmds(batch.Cmds, p.cfg.PluginBatchLimit)
	if err != nil {
		respondWithError(w, r,
			"handleReadBatch: decodeCmds: %v", err)
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
		replies       = make([]v1.CmdReply, len(batch.Cmds))
	)
	for i, cmd := range cmds {
		// Verify plugin exists
		_, ok := p.plugins[cmd.PluginID]
		if !ok {
			replies[i] = v1.CmdReply{
				Error: v1.UserError{
					ErrorCode: v1.ErrorCodePluginNotFound,
				},
			}
			continue
		}

		// Execute the plugin command
		pluginCmd := convertCmdFromHTTP(cmd)
		pluginReply, err := p.execRead(r.Context(), pluginSession, pluginCmd)
		if err != nil {
			respondWithError(w, r,
				"handleReadBatch: execRead: %v", err)
			return
		}

		replies[i] = convertReplyToHTTP(pluginCmd, *pluginReply)
	}

	// Save any updates that were made to the user session
	err = p.saveUserSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed. Handle
		// the error gracefully.
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

	// Check if this a user error
	var ue v1.UserError
	if errors.As(err, &ue) {
		m := fmt.Sprintf("%v User error: %v %v",
			util.RemoteAddr(r), ue.ErrorCode, v1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)

		util.RespondWithJSON(w, http.StatusOK,
			v1.CmdReply{
				Error: ue,
			})
		return
	}

	// This is an internal server error. Log it and return a 500.
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

func decodeCmds(payload string, batchLimit uint32) ([]v1.Cmd, error) {
	var (
		r    = strings.NewReader(payload)
		d    = json.NewDecoder(r)
		cmds = make([]v1.Cmd, 0, batchLimit)
	)

	// Read the opening bracket
	_, err := d.Token()
	if err != nil {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorCodeInvalidInput,
		}
	}

	// Decode the commands
	var count uint32
	for d.More() {
		count++
		if count > batchLimit {
			return nil, v1.UserError{
				ErrorCode:    v1.ErrorCodeBatchLimitExceeded,
				ErrorContext: fmt.Sprintf("max number of cmds is %v", batchLimit),
			}
		}

		var cmd v1.Cmd
		err := d.Decode(&cmd)
		if err != nil {
			return nil, v1.UserError{
				ErrorCode: v1.ErrorCodeInvalidInput,
			}
		}

		cmds = append(cmds, cmd)
	}

	// Read the closing bracket
	_, err = d.Token()
	if err != nil {
		return nil, v1.UserError{
			ErrorCode: v1.ErrorCodeInvalidInput,
		}
	}

	return cmds, nil
}

// convertCmdFromHTTP converts a http v1 Cmd to a plugin Cmd.
func convertCmdFromHTTP(c v1.Cmd) plugin.Cmd {
	return plugin.Cmd{
		PluginID: c.PluginID,
		Version:  c.Version,
		Cmd:      c.Cmd,
		Payload:  c.Payload,
	}
}

// convertCmdFromHTTP converts a plugin Reply to a http v1 CmdReply.
func convertReplyToHTTP(c plugin.Cmd, r plugin.Reply) v1.CmdReply {
	return v1.CmdReply{
		PluginID: c.PluginID,
		Version:  c.Version,
		Cmd:      c.Cmd,
		Payload:  r.Payload,
		Error:    r.Error,
	}
}
