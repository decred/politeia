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

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

func respondWithError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue v1.UserErrorReply
		pe pdclient.Error
	)
	switch {
	case errors.As(err, &ue):
		// Record user error
		m := fmt.Sprintf("Records user error: %v %v %v",
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
			errContext = pe.ErrorReply.ErrorContext
		)
		e := convertPDErrorCode(errCode)
		switch {
		case pluginID != "":
			// politeiad plugin error. Log it and return a 400.
			m := fmt.Sprintf("Plugin error: %v %v %v",
				util.RemoteAddr(r), pluginID, errCode)
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				v1.PluginErrorReply{
					PluginID:     pluginID,
					ErrorCode:    errCode,
					ErrorContext: strings.Join(errContext, ", "),
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
			// politeiad error does correspond to a user error. Log it and
			// return a 400.
			m := fmt.Sprintf("Records user error: %v %v %v",
				util.RemoteAddr(r), e, v1.ErrorCodes[e])
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				v1.UserErrorReply{
					ErrorCode:    e,
					ErrorContext: strings.Join(errContext, ", "),
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
	// Any error statuses that are intentionally omitted means that
	// politeiawww should 500.
	switch pdv1.ErrorStatusT(errCode) {
	case pdv1.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted
	case pdv1.ErrorStatusInvalidChallenge:
		// Intentionally omitted
	case pdv1.ErrorStatusInvalidFilename:
		return v1.ErrorCodeFileNameInvalid
	case pdv1.ErrorStatusInvalidFileDigest:
		return v1.ErrorCodeFileDigestInvalid
	case pdv1.ErrorStatusInvalidBase64:
		return v1.ErrorCodeFilePayloadInvalid
	case pdv1.ErrorStatusInvalidMIMEType:
		return v1.ErrorCodeFileMIMEInvalid
	case pdv1.ErrorStatusUnsupportedMIMEType:
		return v1.ErrorCodeFileMIMEInvalid
	case pdv1.ErrorStatusInvalidRecordStatusTransition:
		return v1.ErrorCodeRecordStatusInvalid
	case pdv1.ErrorStatusEmpty:
		return v1.ErrorCodeRecordStatusInvalid
	case pdv1.ErrorStatusInvalidMDID:
		return v1.ErrorCodeMetadataStreamIDInvalid
	case pdv1.ErrorStatusDuplicateMDID:
		return v1.ErrorCodeMetadataStreamIDInvalid
	case pdv1.ErrorStatusDuplicateFilename:
		return v1.ErrorCodeFileNameInvalid
	case pdv1.ErrorStatusFileNotFound:
		// Intentionally omitted
	case pdv1.ErrorStatusNoChanges:
		return v1.ErrorCodeNoRecordChanges
	case pdv1.ErrorStatusRecordFound:
		// Intentionally omitted
	case pdv1.ErrorStatusInvalidRPCCredentials:
		// Intentionally omitted
	case pdv1.ErrorStatusRecordNotFound:
		return v1.ErrorCodeRecordNotFound
	case pdv1.ErrorStatusInvalidToken:
		return v1.ErrorCodeRecordTokenInvalid
	case pdv1.ErrorStatusRecordLocked:
		return v1.ErrorCodeRecordLocked
	case pdv1.ErrorStatusInvalidRecordState:
		return v1.ErrorCodeRecordStateInvalid
	}
	return v1.ErrorCodeInvalid
}
