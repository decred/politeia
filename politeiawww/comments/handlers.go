// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	pdclient "github.com/decred/politeia/politeiad/client"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/util"
)

func (c *Comments) HandleNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleNew")

	var n cmv1.New
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		respondWithError(w, r, "handleNew: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	usr, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"handleNew: GetSessionUser: %v", err)
		return
	}

	nr, err := c.processNew(r.Context(), n, *usr)
	if err != nil {
		respondWithError(w, r,
			"handleNew: processNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, nr)
}

func (c *Comments) HandleVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleVote")

	var v cmv1.Vote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithError(w, r, "handleVote: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	usr, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"handleVote: GetSessionUser: %v", err)
		return
	}

	vr, err := c.processVote(r.Context(), v, *usr)
	if err != nil {
		respondWithError(w, r,
			"handleVote: processVote: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue cmv1.UserErrorReply
		pe pdclient.Error
	)
	switch {
	case errors.As(err, &ue):
		// Comments user error
		m := fmt.Sprintf("Comments user error: %v %v %v",
			util.RemoteAddr(r), ue.ErrorCode, cmv1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			cmv1.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return

	case errors.As(err, &pe):
		// Politeiad error
		var (
			pluginID   = pe.ErrorReply.PluginID
			errCode    = pe.ErrorReply.ErrorCode
			errContext = pe.ErrorReply.ErrorContext
		)
		switch {
		case pluginID != "":
			// Politeiad plugin error. Log it and return a 400.
			m := fmt.Sprintf("Plugin error: %v %v %v",
				util.RemoteAddr(r), pluginID, errCode)
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				cmv1.PluginErrorReply{
					PluginID:     pluginID,
					ErrorCode:    errCode,
					ErrorContext: strings.Join(errContext, ", "),
				})
			return

		default:
			// Unknown politeiad error. Log it and return a 500.
			ts := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error code "+
				"from politeiad: %v", util.RemoteAddr(r), r.Method, r.URL,
				r.Proto, ts, errCode)

			util.RespondWithJSON(w, http.StatusInternalServerError,
				cmv1.ServerErrorReply{
					ErrorCode: ts,
				})
			return
		}

	default:
		// Internal server error. Log it and return a 500.
		t := time.Now().Unix()
		e := fmt.Sprintf(format, err)
		log.Errorf("%v %v %v %v Internal error %v: %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, e)
		log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

		util.RespondWithJSON(w, http.StatusInternalServerError,
			cmv1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}
