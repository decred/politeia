// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

func (p *politeiawww) processTimestamps(ctx context.Context, t rcv1.Timestamps, isAdmin bool) (*rcv1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v %v", t.State, t.Token, t.Version)

	// Get record timestamps
	var (
		rt  *pdv1.RecordTimestamps
		err error
	)
	switch t.State {
	case rcv1.StateUnvetted:
		rt, err = p.politeiad.GetUnvettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	case rcv1.StateVetted:
		rt, err = p.politeiad.GetVettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	default:
		return nil, rcv1.UserErrorReply{
			ErrorCode: rcv1.ErrorCodeRecordStateInvalid,
		}
	}

	var (
		recordMD = convertTimestampFromPD(rt.RecordMetadata)
		metadata = make(map[uint64]rcv1.Timestamp, len(rt.Files))
		files    = make(map[string]rcv1.Timestamp, len(rt.Files))
	)
	for k, v := range rt.Metadata {
		metadata[k] = convertTimestampFromPD(v)
	}
	for k, v := range rt.Files {
		files[k] = convertTimestampFromPD(v)
	}

	// Unvetted data blobs are stripped if the user is not an admin.
	// The rest of the timestamp is still returned.
	if t.State != rcv1.StateVetted && !isAdmin {
		recordMD.Data = ""
		for k, v := range files {
			v.Data = ""
			files[k] = v
		}
		for k, v := range metadata {
			v.Data = ""
			metadata[k] = v
		}
	}

	return &rcv1.TimestampsReply{
		RecordMetadata: recordMD,
		Files:          files,
		Metadata:       metadata,
	}, nil
}

func (p *politeiawww) handleTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleTimestamps")

	var t rcv1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithRecordError(w, r, "handleTimestamps: unmarshal",
			rcv1.UserErrorReply{
				ErrorCode: rcv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithRecordError(w, r,
			"handleTimestamps: getSessionUser: %v", err)
		return
	}

	isAdmin := usr != nil && usr.Admin
	tr, err := p.processTimestamps(r.Context(), t, isAdmin)
	if err != nil {
		respondWithRecordError(w, r,
			"handleTimestamps: processTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tr)
}

func convertRecordsErrorCode(errCode int) rcv1.ErrorCodeT {
	switch pdv1.ErrorStatusT(errCode) {
	case pdv1.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted. This indicates an internal server error.
	case pdv1.ErrorStatusInvalidChallenge:
		// Intentionally omitted. This indicates an internal server error.
	case pdv1.ErrorStatusRecordNotFound:
		return rcv1.ErrorCodeRecordNotFound
	}
	// No record API error code found
	return rcv1.ErrorCodeInvalid
}

func respondWithRecordError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue rcv1.UserErrorReply
		pe pdError
	)
	switch {
	case errors.As(err, &ue):
		// Record user error
		m := fmt.Sprintf("Records user error: %v %v %v",
			remoteAddr(r), ue.ErrorCode, rcv1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			rcv1.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return

	case errors.As(err, &pe):
		// Politeiad error
		var (
			pluginID   = pe.ErrorReply.Plugin
			errCode    = pe.ErrorReply.ErrorCode
			errContext = pe.ErrorReply.ErrorContext
		)
		e := convertRecordsErrorCode(errCode)
		switch {
		case pluginID != "":
			// politeiad plugin error. Log it and return a 400.
			m := fmt.Sprintf("Plugin error: %v %v %v",
				remoteAddr(r), pluginID, errCode)
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				rcv1.PluginErrorReply{
					PluginID:     pluginID,
					ErrorCode:    errCode,
					ErrorContext: strings.Join(errContext, ", "),
				})
			return

		case e == rcv1.ErrorCodeInvalid:
			// politeiad error does not correspond to a user error. Log it
			// and return a 500.
			ts := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error code "+
				"from politeiad: %v", remoteAddr(r), r.Method, r.URL,
				r.Proto, ts, errCode)

			util.RespondWithJSON(w, http.StatusInternalServerError,
				rcv1.ServerErrorReply{
					ErrorCode: ts,
				})
			return

		default:
			// politeiad error does correspond to a user error. Log it and
			// return a 400.
			m := fmt.Sprintf("Records user error: %v %v %v",
				remoteAddr(r), e, rcv1.ErrorCodes[e])
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				rcv1.UserErrorReply{
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
			remoteAddr(r), r.Method, r.URL, r.Proto, t, e)
		log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

		util.RespondWithJSON(w, http.StatusInternalServerError,
			rcv1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}

func convertProofFromPD(p pdv1.Proof) rcv1.Proof {
	return rcv1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampFromPD(t pdv1.Timestamp) rcv1.Timestamp {
	proofs := make([]rcv1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofFromPD(v))
	}
	return rcv1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
