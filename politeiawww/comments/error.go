// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/util"
)

func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue v1.UserErrorReply
		pe pdclient.Error
	)
	switch {
	case errors.As(err, &ue):
		// Comments user error
		m := fmt.Sprintf("%v Records user error: %v %v",
			util.RemoteAddr(r), ue.ErrorCode, v1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			v1.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return

	case errors.As(err, &pe):
		// Politeiad error
		var (
			pluginID   = pe.ErrorReply.PluginID
			errCode    = pe.ErrorReply.ErrorCode
			errContext = strings.Join(pe.ErrorReply.ErrorContext, ",")
		)
		e := convertPDErrorCode(errCode)
		switch {
		case pluginID != "":
			// politeiad plugin error. Log it and return a 400.
			m := fmt.Sprintf("%v Plugin error: %v %v",
				util.RemoteAddr(r), pluginID, errCode)
			if errContext != "" {
				m += fmt.Sprintf(": %v", errContext)
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				v1.PluginErrorReply{
					PluginID:     pluginID,
					ErrorCode:    errCode,
					ErrorContext: errContext,
				})
			return

		case e == v1.ErrorCodeInvalid:
			// politeiad error does not correspond to a user error. Log it
			// and return a 500.
			ts := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error code "+
				"from politeiad: %v", util.RemoteAddr(r), r.Method, r.URL,
				r.Proto, ts, errCode)

			util.RespondWithJSON(w, http.StatusInternalServerError,
				v1.ServerErrorReply{
					ErrorCode: ts,
				})
			return

		default:
			// User error from politeiad that corresponds to a comments
			// user error. Log it and return a 400.
			m := fmt.Sprintf("%v Records user error: %v %v",
				util.RemoteAddr(r), e, v1.ErrorCodes[e])
			if errContext != "" {
				m += fmt.Sprintf(": %v", errContext)
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				v1.UserErrorReply{
					ErrorCode:    e,
					ErrorContext: errContext,
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
			v1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}

func convertPDErrorCode(errCode int) v1.ErrorCodeT {
	// These are the only politeiad user errors that the comments
	// API expects to encounter.
	switch pdv1.ErrorStatusT(errCode) {
	case pdv1.ErrorStatusInvalidToken:
		return v1.ErrorCodeTokenInvalid
	case pdv1.ErrorStatusInvalidRecordState:
		return v1.ErrorCodeRecordStateInvalid
	case pdv1.ErrorStatusRecordNotFound:
		return v1.ErrorCodeRecordNotFound
	case pdv1.ErrorStatusRecordLocked:
		return v1.ErrorCodeRecordLocked
	}
	return v1.ErrorCodeInvalid
}
