// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	// Check if the client dropped the connection
	if err := r.Context().Err(); err == context.Canceled {
		log.Infof("%v %v %v %v client aborted connection",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// Client dropped the connection. There is no need to
		// respond further.
		return
	}

	// Check for expected error types
	var (
		ue  v1.UserErrorReply
		pe  v1.PluginErrorReply
		pde pdclient.RespError
	)
	switch {
	case errors.As(err, &ue):
		// Records user error
		m := fmt.Sprintf("%v Pi user error: %v %v",
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
		// politeiawww plugin error
		m := fmt.Sprintf("%v Plugin error: %v %v",
			util.RemoteAddr(r), pe.PluginID, pe.ErrorCode)
		if pe.ErrorContext != "" {
			m += fmt.Sprintf(": %v", pe.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			v1.PluginErrorReply{
				PluginID:     pe.PluginID,
				ErrorCode:    pe.ErrorCode,
				ErrorContext: pe.ErrorContext,
			})
		return

	case errors.As(err, &pde):
		// Politeiad error
		handlePDError(w, r, format, pde)

	default:
		// Internal server error. Log it and return a 500.
		t := time.Now().Unix()
		e := fmt.Sprintf(format, err)
		log.Errorf("%v %v %v %v Internal error %v: %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, e)

		// If this is a pkg/errors error then we can pull the
		// stack trace out of the error, otherwise, we use the
		// stack trace for this function.
		stack, ok := util.StackTrace(err)
		if !ok {
			stack = string(debug.Stack())
		}

		log.Errorf("Stacktrace (NOT A REAL CRASH): %v", stack)

		util.RespondWithJSON(w, http.StatusInternalServerError,
			v1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}

// handlePDError handles errors from politeiad.
func handlePDError(w http.ResponseWriter, r *http.Request, format string, pde pdclient.RespError) {
	var (
		pluginID   = pde.ErrorReply.PluginID
		errCode    = pde.ErrorReply.ErrorCode
		errContext = pde.ErrorReply.ErrorContext
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

	case e != v1.ErrorCodeInvalid:
		// User error from politeiad that corresponds to a records user
		// error. Log it and return a 400.
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

	default:
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
	}
}

// convertPDErrorCode converts user errors from politeiad into pi user errors.
func convertPDErrorCode(errCode uint32) v1.ErrorCodeT {
	// Any error statuses that are intentionally omitted means that
	// politeiawww should 500.
	switch pdv2.ErrorCodeT(errCode) {
	case pdv2.ErrorCodeTokenInvalid:
		return v1.ErrorCodeRecordTokenInvalid
	case pdv2.ErrorCodeRecordNotFound:
		return v1.ErrorCodeRecordNotFound
	case pdv2.ErrorCodeRequestPayloadInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeChallengeInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeMetadataStreamInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeMetadataStreamDuplicate:
		// Intentionally omitted
	case pdv2.ErrorCodeFilesEmpty:
		// Intentionally omitted
	case pdv2.ErrorCodeFileNameInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeFileNameDuplicate:
		// Intentionally omitted
	case pdv2.ErrorCodeFileDigestInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeFilePayloadInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeFileMIMETypeInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeFileMIMETypeUnsupported:
		// Intentionally omitted
	case pdv2.ErrorCodeRecordLocked:
		// Intentionally omitted
	case pdv2.ErrorCodeNoRecordChanges:
		// Intentionally omitted
	case pdv2.ErrorCodeStatusChangeInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodePluginIDInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodePluginCmdInvalid:
		// Intentionally omitted
	}
	return v1.ErrorCodeInvalid
}
