// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/decred/politeia/app"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
)

// handleNotFound handles all invalid routes and returns a 404 to the client.
func (p *politeiawww) handleNotFound(w http.ResponseWriter, r *http.Request) {
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

// handleVersion is the request handler for the http v3 VersionRoute.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	// Set the CSRF header. This is the only route
	// that sets the CSRF header.
	w.Header().Set(v3.CSRFTokenHeader, csrf.Token(r))

	vr := v3.VersionReply{
		APIVersion:   v3.APIVersion,
		BuildVersion: version.String(),
	}

	respondWithOK(w, vr)
}

// handlePolicy is the request handler for the http v3 PolicyRoute.
func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePolicy")

	pr := v3.PolicyReply{
		ReadBatchLimit: p.cfg.PluginBatchLimit,
	}

	respondWithOK(w, pr)
}

// handleWrite is the request handler for the http v3 WriteRoute.
func (p *politeiawww) handleWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWrite")

	// Decode the request body
	var cmd v3.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		respondWithUserError(w, r, v3.ErrCodeInvalidInput, "")
		return
	}

	// Verify the plugin command
	cs := cmdStr(cmd.Plugin, cmd.Version, cmd.Name)
	_, ok := p.cmds[cs]
	if !ok {
		respondWithUserError(w, r, v3.ErrCodeInvalidPluginCmd, "")
		return
	}

	// Extract the session data from the request cookies
	s, err := p.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}
	as := app.NewSession(s.Values)

	// Execute the plugin command
	reply, err := p.writeCmd(r.Context(), as, cmd)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	log.Infof("Executed write %v", cs)

	// Save any updates that were made to the session
	p.UpdateSession(r, w, s, as)

	// Send the response
	respondWithOK(w, reply)
}

// handleRead is the request handler for the http v3 ReadRoute.
func (p *politeiawww) handleRead(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRead")

	// Decode the request body
	var cmd v3.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		respondWithUserError(w, r, v3.ErrCodeInvalidInput, "")
		return
	}

	// Verify the plugin command
	cs := cmdStr(cmd.Plugin, cmd.Version, cmd.Name)
	_, ok := p.cmds[cs]
	if !ok {
		respondWithUserError(w, r, v3.ErrCodeInvalidPluginCmd, "")
		return
	}

	// Extract the session data from the request cookies
	s, err := p.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}
	as := app.NewSession(s.Values)

	// Execute the plugin command
	reply, err := p.readCmd(r.Context(), as, cmd)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	log.Infof("Executed read %v", cs)

	// Save any updates that were made to the session
	p.UpdateSession(r, w, s, as)

	// Send the response
	respondWithOK(w, reply)
}

// cmdStr returns a string representation of a plugin command.
func cmdStr(pluginID string, version uint32, cmdName string) string {
	c := app.CmdDetails{
		Plugin:  pluginID,
		Version: version,
		Name:    cmdName,
	}
	return c.String()
}

/*
// handleReadBatch is the request handler for the http v3 ReadBatchRoute.
func (p *politeiawww) handleReadBatch(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleReadBatch")

	// Decode the request body
	var batch v3.Batch
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&batch); err != nil {
		respondWithUserError(w, r, v3.ErrCodeInvalidInput, "")
		return
	}

	// Verify the batched commands
	if len(batch.Cmds) > int(p.cfg.PluginBatchLimit) {
		c := fmt.Sprintf("max number of batch cmds is %v", p.cfg.PluginBatchLimit)
		respondWithUserError(w, r, v3.ErrCodeBatchLimitExceeded, c)
		return
	}
	notFound := make([]string, 0, len(batch.Cmds))
	for _, cmd := range batch.Cmds {
		_, ok := p.plugins[cmd.Plugin]
		if !ok {
			notFound = append(notFound, cmd.Plugin)
		}
	}
	if len(notFound) > 0 {
		c := strings.Join(notFound, ", ")
		respondWithUserError(w, r, v3.ErrCodePluginNotFound, c)
		return
	}

	// Extract the session data from the request cookies
	s, err := p.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	// Execute the plugin commands
	var (
		pluginSession = convertSession(s)
		replies       = make([]v3.CmdReply, len(batch.Cmds))
	)
	for i, cmd := range batch.Cmds {
		pluginCmd := convertCmd(cmd)
		pluginReply, err := p.readCmd(r.Context(), pluginSession, pluginCmd)
		if err != nil {
			respondWithInternalError(w, r, err)
			return
		}

		replies[i] = convertReplyToHTTP(pluginCmd, *pluginReply)
	}

	// Save any updates that were made to the user session
	err = p.updateSession(r, w, s, pluginSession)
	if err != nil {
		// The plugin command has already been executed. Handle
		// the error gracefully.
		log.Errorf("handleReadBatch: updateSession: %v", err)
	}

	// Send the response
	respondWithOK(w, v3.BatchReply{Replies: replies})
}
*/

// respondWithOK responses to the client request with a 200 http status code
// and the JSON encoded body.
func respondWithOK(w http.ResponseWriter, body interface{}) {
	util.RespondWithJSON(w, http.StatusOK, body)
}

// respondWithUserError responds to the client request with a 400 http status
// code and a JSON encoded v3 UserError in the response body.
func respondWithUserError(w http.ResponseWriter, r *http.Request, errCode v3.ErrCode, errContext string) {
	m := fmt.Sprintf("%v User error: %v %v",
		util.RemoteAddr(r), errCode, v3.ErrCodes[errCode])
	if errContext != "" {
		m += fmt.Sprintf("- %v", errContext)
	}
	log.Infof(m)

	util.RespondWithJSON(w, http.StatusBadRequest,
		v3.UserError{
			ErrorCode:    errCode,
			ErrorContext: errContext,
		})
}

// respondWithInternalError responds to the client request with a 500 http
// status code and a JSON encoded v3 InternalError in the response body.
func respondWithInternalError(w http.ResponseWriter, r *http.Request, err error) {
	// Check if the client dropped the connection. There
	// is no need to send a response if the client dropped
	// the connection.
	if err := r.Context().Err(); err == context.Canceled {
		log.Infof("%v %v %v %v client aborted connection",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)
		return
	}

	// Log an internal server error
	t := time.Now().Unix()
	log.Errorf("%v %v %v %v Internal error %v: %v",
		util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, err)

	// If this is a pkg/errors error then we can pull the
	// stack trace out of the error, otherwise, we use the
	// stack trace of this function invocation.
	stack, ok := util.StackTrace(err)
	if ok {
		log.Errorf("Stacktrace (NOT A REAL CRASH): %v", stack)
	}

	util.RespondWithJSON(w, http.StatusInternalServerError,
		v3.InternalError{
			ErrorCode: t,
		})
}
