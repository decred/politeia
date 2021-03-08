// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue  v1.UserErrorReply
		pe  v1.PluginErrorReply
		pde pdclient.Error
	)
	switch {
	case errors.As(err, &ue):
		// Records user error
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
		log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

		util.RespondWithJSON(w, http.StatusInternalServerError,
			v1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}

func handlePDError(w http.ResponseWriter, r *http.Request, format string, pde pdclient.Error) {
	var (
		pluginID   = pde.ErrorReply.PluginID
		errCode    = pde.ErrorReply.ErrorCode
		errContext = strings.Join(pde.ErrorReply.ErrorContext, ",")
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

func convertPDErrorCode(errCode int) v1.ErrorCodeT {
	// Any error statuses that are intentionally omitted means that
	// politeiawww should 500.
	switch pdv2.ErrorCodeT(errCode) {
	case pdv2.ErrorCodeRequestPayloadInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeChallengeInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeMetadataStreamInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodeMetadataStreamDuplicate:
		// Intentionally omitted
	case pdv2.ErrorCodeFilesEmpty:
		return v1.ErrorCodeFilesEmpty
	case pdv2.ErrorCodeFileNameInvalid:
		return v1.ErrorCodeFileNameInvalid
	case pdv2.ErrorCodeFileNameDuplicate:
		return v1.ErrorCodeFileNameDuplicate
	case pdv2.ErrorCodeFileDigestInvalid:
		return v1.ErrorCodeFileDigestInvalid
	case pdv2.ErrorCodeFilePayloadInvalid:
		return v1.ErrorCodeFilePayloadInvalid
	case pdv2.ErrorCodeFileMIMETypeInvalid:
		return v1.ErrorCodeFileMIMETypeInvalid
	case pdv2.ErrorCodeFileMIMETypeUnsupported:
		return v1.ErrorCodeFileMIMETypeUnsupported
	case pdv2.ErrorCodeTokenInvalid:
		return v1.ErrorCodeRecordTokenInvalid
	case pdv2.ErrorCodeRecordNotFound:
		return v1.ErrorCodeRecordNotFound
	case pdv2.ErrorCodeRecordLocked:
		return v1.ErrorCodeRecordLocked
	case pdv2.ErrorCodeNoRecordChanges:
		return v1.ErrorCodeNoRecordChanges
	case pdv2.ErrorCodeStatusChangeInvalid:
		return v1.ErrorCodeStatusChangeInvalid
	case pdv2.ErrorCodePluginIDInvalid:
		// Intentionally omitted
	case pdv2.ErrorCodePluginCmdInvalid:
		// Intentionally omitted
	}
	return v1.ErrorCodeInvalid
}
