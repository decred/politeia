// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/decred/politeia/app"
	"github.com/decred/politeia/politeiawww/logger"
	v1 "github.com/decred/politeia/server/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/csrf"
)

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

// handleVersion is the request handler for the http v1 VersionRoute.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	// Set the CSRF header. This is the only route
	// that sets the CSRF header.
	w.Header().Set(v1.CSRFTokenHeader, csrf.Token(r))

	vr := v1.VersionReply{
		BuildVersion: s.cfg.BuildVersion,
		APIVersion:   v1.APIVersion,
	}

	respondWithOK(w, vr)
}

// handlePolicy is the request handler for the http v1 PolicyRoute.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePolicy")

	pr := v1.PolicyReply{
		SessionMaxAge:  s.cfg.SessionMaxAge,
		ReadBatchLimit: s.cfg.PluginBatchLimit,
	}

	respondWithOK(w, pr)
}

// handleWrite is the request handler for the http v1 WriteRoute.
func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWrite")

	// Decode the request body
	var cmd v1.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		respondWithUserError(w, r, v1.ErrCodeInvalidInput, "")
		return
	}

	// Verify the plugin command
	cs := cmdStr(cmd.Plugin, cmd.Version, cmd.Name)
	_, ok := s.cmds[cs]
	if !ok {
		respondWithUserError(w, r, v1.ErrCodeInvalidPluginCmd, "")
		return
	}

	log.Infof("%v Exec %v", util.RemoteAddr(r), cs)

	// Extract the session data from the request cookies
	sn, err := s.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}
	asn := app.NewSession(sn.Values)

	// Execute the plugin command
	reply, err := s.writeCmd(r.Context(), asn, cmd)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	// Save any updates that were made to the session
	err = s.updateSession(r, w, sn, asn)
	if err != nil {
		// Session updates occur after plugin command has already
		// completed. If the plugin command executes successfully
		// then the server response must reflect this. For this
		// reason, any errors that occur during a session update
		// are handled gracefully and logged, rather than returning
		// an error to the user.
		log.Errorf("updateSession %+v: %v", asn, err)
	}

	// Send the response
	respondWithOK(w, reply)
}

// handleRead is the request handler for the http v1 ReadRoute.
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRead")

	// Decode the request body
	var cmd v1.Cmd
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cmd); err != nil {
		respondWithUserError(w, r, v1.ErrCodeInvalidInput, "")
		return
	}

	// Verify the plugin command
	cs := cmdStr(cmd.Plugin, cmd.Version, cmd.Name)
	_, ok := s.cmds[cs]
	if !ok {
		respondWithUserError(w, r, v1.ErrCodeInvalidPluginCmd, "")
		return
	}

	log.Infof("%v Exec %v", util.RemoteAddr(r), cs)

	// Extract the session data from the request cookies
	sn, err := s.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}
	asn := app.NewSession(sn.Values)

	// Execute the plugin command
	reply, err := s.readCmd(r.Context(), *asn, cmd)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	// Read commands aren't allowed to update the
	// user session, so we don't need to check.

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
// handleReadBatch is the request handler for the http v1 ReadBatchRoute.
func (s *Server) handleReadBatch(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleReadBatch")

	// Decode the request body
	var batch v1.Batch
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&batch); err != nil {
		respondWithUserError(w, r, v1.ErrCodeInvalidInput, "")
		return
	}

	// Verify the batched commands
	if len(batch.Cmds) > int(s.cfg.PluginBatchLimit) {
		c := fmt.Sprintf("max number of batch cmds is %v", s.cfg.PluginBatchLimit)
		respondWithUserError(w, r, v1.ErrCodeBatchLimitExceeded, c)
		return
	}
	notFound := make([]string, 0, len(batch.Cmds))
	for _, cmd := range batch.Cmds {
		_, ok := s.plugins[cmd.Plugin]
		if !ok {
			notFound = append(notFound, cmd.Plugin)
		}
	}
	if len(notFound) > 0 {
		c := strings.Join(notFound, ", ")
		respondWithUserError(w, r, v1.ErrCodePluginNotFound, c)
		return
	}

	// Extract the session data from the request cookies
	s, err := s.extractSession(r)
	if err != nil {
		respondWithInternalError(w, r, err)
		return
	}

	// Execute the plugin commands
	var (
		pluginSession = convertSession(s)
		replies       = make([]v1.CmdReply, len(batch.Cmds))
	)
	for i, cmd := range batch.Cmds {
		pluginCmd := convertCmd(cmd)
		pluginReply, err := s.readCmd(r.Context(), pluginSession, pluginCmd)
		if err != nil {
			respondWithInternalError(w, r, err)
			return
		}

		replies[i] = convertReplyToHTTP(pluginCmd, *pluginReply)
	}

	// Read commands aren't allowed to update the
	// user session, so we don't need to check.

	// Send the response
	respondWithOK(w, v1.BatchReply{Replies: replies})
}
*/

// respondWithOK responses to the client request with a 200 http status code
// and the JSON encoded body.
func respondWithOK(w http.ResponseWriter, body interface{}) {
	util.RespondWithJSON(w, http.StatusOK, body)
}

// respondWithUserError responds to the client request with a 400 http status
// code and a JSON encoded v1 UserError in the response body.
func respondWithUserError(w http.ResponseWriter, r *http.Request, errCode v1.ErrCode, errContext string) {
	m := fmt.Sprintf("%v User error: %v %v",
		util.RemoteAddr(r), errCode, v1.ErrCodes[errCode])
	if errContext != "" {
		m += fmt.Sprintf("- %v", errContext)
	}
	log.Infof(m)

	util.RespondWithJSON(w, http.StatusBadRequest,
		v1.UserError{
			ErrorCode:    errCode,
			ErrorContext: errContext,
		})
}

// respondWithInternalError responds to the client request with a 500 http
// status code and a JSON encoded v1 InternalError in the response body.
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
	e := fmt.Sprintf("%v %v %v %v Internal error %v: %v",
		util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, err)

	// If this is a pkg/errors error then we can pull the
	// stack trace out of the error, otherwise, we use the
	// stack trace of this function invocation.
	stack, ok := util.StackTrace(err)
	if ok {
		e += fmt.Sprintf("\nInternal error stacktrace (NOT A PANIC): %v", stack)
	}

	log.Error(e)

	util.RespondWithJSON(w, http.StatusInternalServerError,
		v1.InternalError{
			ErrorCode: t,
		})
}
