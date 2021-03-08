// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/mux"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionAuth
)

// politeia application context.
type politeia struct {
	backend   backend.Backend
	backendv2 backendv2.Backend
	cfg       *config
	router    *mux.Router
	identity  *identity.FullIdentity
}

func remoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(v1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}

func convertBackendPluginSetting(bpi backend.PluginSetting) v1.PluginSetting {
	return v1.PluginSetting{
		Key:   bpi.Key,
		Value: bpi.Value,
	}
}

func convertBackendPlugins(bplugins []backend.Plugin) []v1.Plugin {
	plugins := make([]v1.Plugin, 0, len(bplugins))
	for _, v := range bplugins {
		p := v1.Plugin{
			ID:       v.ID,
			Version:  v.Version,
			Settings: make([]v1.PluginSetting, 0, len(v.Settings)),
		}
		for _, v := range v.Settings {
			p.Settings = append(p.Settings, convertBackendPluginSetting(v))
		}
		plugins = append(plugins, p)
	}
	return plugins
}

// convertBackendMetadataStream converts a backend metadata stream to an API
// metadata stream.
func convertBackendMetadataStream(mds backend.MetadataStream) v1.MetadataStream {
	return v1.MetadataStream{
		ID:      mds.ID,
		Payload: mds.Payload,
	}
}

// convertBackendStatus converts a backend MDStatus to an API status.
func convertBackendStatus(status backend.MDStatusT) v1.RecordStatusT {
	s := v1.RecordStatusInvalid
	switch status {
	case backend.MDStatusInvalid:
		s = v1.RecordStatusInvalid
	case backend.MDStatusUnvetted:
		s = v1.RecordStatusNotReviewed
	case backend.MDStatusVetted:
		s = v1.RecordStatusPublic
	case backend.MDStatusCensored:
		s = v1.RecordStatusCensored
	case backend.MDStatusIterationUnvetted:
		s = v1.RecordStatusUnreviewedChanges
	case backend.MDStatusArchived:
		s = v1.RecordStatusArchived
	}
	return s
}

// convertFrontendStatus convert an API status to a backend MDStatus.
func convertFrontendStatus(status v1.RecordStatusT) backend.MDStatusT {
	s := backend.MDStatusInvalid
	switch status {
	case v1.RecordStatusInvalid:
		s = backend.MDStatusInvalid
	case v1.RecordStatusNotReviewed:
		s = backend.MDStatusUnvetted
	case v1.RecordStatusPublic:
		s = backend.MDStatusVetted
	case v1.RecordStatusCensored:
		s = backend.MDStatusCensored
	case v1.RecordStatusArchived:
		s = backend.MDStatusArchived
	}
	return s
}

func convertFrontendFiles(f []v1.File) []backend.File {
	files := make([]backend.File, 0, len(f))
	for _, v := range f {
		files = append(files, backend.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertFrontendMetadataStream(mds []v1.MetadataStream) []backend.MetadataStream {
	m := make([]backend.MetadataStream, 0, len(mds))
	for _, v := range mds {
		m = append(m, backend.MetadataStream{
			ID:      v.ID,
			Payload: v.Payload,
		})
	}
	return m
}

func (p *politeia) convertBackendRecord(br backend.Record) v1.Record {
	rm := br.RecordMetadata

	// Calculate signature
	signature := p.identity.SignMessage([]byte(rm.Merkle + rm.Token))

	// Convert MetadataStream
	md := make([]v1.MetadataStream, 0, len(br.Metadata))
	for k := range br.Metadata {
		md = append(md, convertBackendMetadataStream(br.Metadata[k]))
	}

	// Convert record
	pr := v1.Record{
		Status:    convertBackendStatus(rm.Status),
		Timestamp: rm.Timestamp,
		CensorshipRecord: v1.CensorshipRecord{
			Merkle:    rm.Merkle,
			Token:     rm.Token,
			Signature: hex.EncodeToString(signature[:]),
		},
		Version:  br.Version,
		Metadata: md,
	}
	pr.Files = make([]v1.File, 0, len(br.Files))
	for _, v := range br.Files {
		pr.Files = append(pr.Files,
			v1.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
	}

	return pr
}

// handleNotFound is a generic handler for an invalid route.
func (p *politeia) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// Log incoming connection
	log.Debugf("Invalid route: %v %v %v %v", remoteAddr(r), r.Method, r.URL,
		r.Proto)

	// Trace incoming request
	log.Tracef("%v", newLogClosure(func() string {
		trace, err := httputil.DumpRequest(r, true)
		if err != nil {
			trace = []byte(fmt.Sprintf("logging: "+
				"DumpRequest %v", err))
		}
		return string(trace)
	}))

	util.RespondWithJSON(w, http.StatusNotFound, v1.ServerErrorReply{})
}

func (p *politeia) respondWithUserError(w http.ResponseWriter, errorCode v1.ErrorStatusT, errorContext []string) {
	util.RespondWithJSON(w, http.StatusBadRequest, v1.UserErrorReply{
		ErrorCode:    errorCode,
		ErrorContext: errorContext,
	})
}

func (p *politeia) respondWithServerError(w http.ResponseWriter, errorCode int64) {
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())
	util.RespondWithJSON(w, http.StatusInternalServerError, v1.ServerErrorReply{
		ErrorCode: errorCode,
	})
}

func (p *politeia) getIdentity(w http.ResponseWriter, r *http.Request) {
	var t v1.Identity
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.IdentityReply{
		PublicKey: hex.EncodeToString(p.identity.Public.Key[:]),
		Response:  hex.EncodeToString(response[:]),
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) newRecord(w http.ResponseWriter, r *http.Request) {
	var t v1.NewRecord
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		log.Infof("%v newRecord: invalid challenge", remoteAddr(r))
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	md := convertFrontendMetadataStream(t.Metadata)
	files := convertFrontendFiles(t.Files)
	rm, err := p.backend.New(md, files)
	if err != nil {
		// Check for content error.
		var contentErr backend.ContentVerificationError
		if errors.As(err, &contentErr) {
			log.Infof("%v New record content error: %v",
				remoteAddr(r), contentErr)
			p.respondWithUserError(w, contentErr.ErrorCode,
				contentErr.ErrorContext)
			return
		}

		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v New record error code %v: %v", remoteAddr(r),
			errorCode, err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply.
	signature := p.identity.SignMessage([]byte(rm.Merkle + rm.Token))

	response := p.identity.SignMessage(challenge)
	reply := v1.NewRecordReply{
		Response: hex.EncodeToString(response[:]),
		CensorshipRecord: v1.CensorshipRecord{
			Merkle:    rm.Merkle,
			Token:     rm.Token,
			Signature: hex.EncodeToString(signature[:]),
		},
	}

	log.Infof("New record accepted %v: token %v", remoteAddr(r),
		reply.CensorshipRecord.Token)

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) updateRecord(w http.ResponseWriter, r *http.Request, vetted bool) {
	cmd := "unvetted"
	if vetted {
		cmd = "vetted"
	}

	var t v1.UpdateRecord
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload,
			nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		log.Infof("%v update %v record: invalid challenge",
			remoteAddr(r), cmd)
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	log.Infof("Update %v record submitted %v: %x", cmd, remoteAddr(r),
		token)

	var record *backend.Record
	if vetted {
		record, err = p.backend.UpdateVettedRecord(token,
			convertFrontendMetadataStream(t.MDAppend),
			convertFrontendMetadataStream(t.MDOverwrite),
			convertFrontendFiles(t.FilesAdd), t.FilesDel)
	} else {
		record, err = p.backend.UpdateUnvettedRecord(token,
			convertFrontendMetadataStream(t.MDAppend),
			convertFrontendMetadataStream(t.MDOverwrite),
			convertFrontendFiles(t.FilesAdd), t.FilesDel)
	}
	if err != nil {
		if errors.Is(err, backend.ErrRecordFound) {
			log.Infof("%v update %v record found: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusRecordFound,
				nil)
			return
		}
		if errors.Is(err, backend.ErrRecordNotFound) {
			log.Infof("%v update %v record not found: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusRecordNotFound, nil)
			return
		}
		if errors.Is(err, backend.ErrNoChanges) {
			log.Infof("%v update %v record no changes: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusNoChanges, nil)
			return
		}
		// Check for content error.
		var contentErr backend.ContentVerificationError
		if errors.As(err, &contentErr) {
			log.Infof("%v update %v record content error: %v",
				remoteAddr(r), cmd, contentErr)
			p.respondWithUserError(w, contentErr.ErrorCode,
				contentErr.ErrorContext)
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Update %v record error code %v: %v",
			remoteAddr(r), cmd, errorCode, err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply.
	response := p.identity.SignMessage(challenge)
	reply := v1.UpdateRecordReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertBackendRecord(*record),
	}

	log.Infof("Update %v record %v: token %v", cmd, remoteAddr(r),
		record.RecordMetadata.Token)

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) updateUnvetted(w http.ResponseWriter, r *http.Request) {
	p.updateRecord(w, r, false)
}

func (p *politeia) updateVetted(w http.ResponseWriter, r *http.Request) {
	p.updateRecord(w, r, true)
}

func (p *politeia) getUnvetted(w http.ResponseWriter, r *http.Request) {
	var t v1.GetUnvetted
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.GetUnvettedReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetUnvetted(token, t.Version)
	switch {
	case errors.Is(err, backend.ErrRecordNotFound):
		// Record not found
		log.Infof("Get unvetted record %v: token %v not found",
			remoteAddr(r), t.Token)
		p.respondWithUserError(w, v1.ErrorStatusRecordNotFound, nil)
		return

	case err != nil:
		// Generic internal error
		errorCode := time.Now().Unix()
		log.Errorf("%v Get unvetted record error code %v: %v",
			remoteAddr(r), errorCode, err)
		p.respondWithServerError(w, errorCode)
		return

	case bpr.RecordMetadata.Status == backend.MDStatusCensored:
		// Record has been censored. The default case will verify the
		// record before sending it off. This will fail for censored
		// records since the files will not exist, they've been deleted,
		// so skip the verification step.
		reply.Record = p.convertBackendRecord(*bpr)
		log.Infof("Get unvetted record %v: token %v", remoteAddr(r), t.Token)

	default:
		reply.Record = p.convertBackendRecord(*bpr)

		// Double check record bits before sending them off
		err := v1.Verify(p.identity.Public,
			reply.Record.CensorshipRecord, reply.Record.Files)
		if err != nil {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v Get unvetted record CORRUPTION "+
				"error code %v: %v", remoteAddr(r), errorCode,
				err)
			p.respondWithServerError(w, errorCode)
			return
		}

		log.Infof("Get unvetted record %v: token %v", remoteAddr(r), t.Token)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) getVetted(w http.ResponseWriter, r *http.Request) {
	var t v1.GetVetted
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.GetVettedReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetVetted(token, t.Version)
	switch {
	case errors.Is(err, backend.ErrRecordNotFound):
		// Record not found
		log.Infof("Get vetted record %v: token %v not found",
			remoteAddr(r), t.Token)
		p.respondWithUserError(w, v1.ErrorStatusRecordNotFound, nil)
		return

	case err != nil:
		// Generic internal error
		errorCode := time.Now().Unix()
		log.Errorf("%v Get vetted record error code %v: %v",
			remoteAddr(r), errorCode, err)
		p.respondWithServerError(w, errorCode)
		return

	case bpr.RecordMetadata.Status == backend.MDStatusCensored:
		// Record has been censored. The default case will verify the
		// record before sending it off. This will fail for censored
		// records since the files will not exist, they've been deleted,
		// so skip the verification step.
		reply.Record = p.convertBackendRecord(*bpr)
		log.Infof("Get vetted record %v: token %v", remoteAddr(r), t.Token)

	default:
		reply.Record = p.convertBackendRecord(*bpr)

		// Double check record bits before sending them off
		err := v1.Verify(p.identity.Public,
			reply.Record.CensorshipRecord, reply.Record.Files)
		if err != nil {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v Get vetted record CORRUPTION "+
				"error code %v: %v", remoteAddr(r), errorCode,
				err)
			p.respondWithServerError(w, errorCode)
			return
		}

		log.Infof("Get vetted record %v: token %v", remoteAddr(r), t.Token)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) convertBackendRecords(br map[string]backend.Record) map[string]v1.Record {
	r := make(map[string]v1.Record, len(br))
	for k, v := range br {
		r[k] = p.convertBackendRecord(v)
	}
	return r
}

func (p *politeia) inventory(w http.ResponseWriter, r *http.Request) {
	var i v1.Inventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(i.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	reply := v1.InventoryReply{
		Response: hex.EncodeToString(response[:]),
	}

	// Ask backend for inventory
	prs, brs, err := p.backend.Inventory(i.VettedCount, i.VettedStart, i.BranchesCount,
		i.IncludeFiles, i.AllVersions)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Inventory error code %v: %v", remoteAddr(r),
			errorCode, err)

		p.respondWithServerError(w, errorCode)
		return
	}

	// Convert backend records
	vetted := make([]v1.Record, 0, len(prs))
	for _, v := range prs {
		vetted = append(vetted, p.convertBackendRecord(v))
	}
	reply.Vetted = vetted

	// Convert branches
	unvetted := make([]v1.Record, 0, len(brs))
	for _, v := range brs {
		unvetted = append(unvetted, p.convertBackendRecord(v))
	}
	reply.Branches = unvetted

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) check(user, pass string) bool {
	if user != p.cfg.RPCUser || pass != p.cfg.RPCPass {
		return false
	}
	return true
}

func (p *politeia) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !p.check(user, pass) {
			log.Infof("%v Unauthorized access for: %v",
				remoteAddr(r), user)
			w.Header().Set("WWW-Authenticate",
				`Basic realm="Politeiad"`)
			w.WriteHeader(401)
			p.respondWithUserError(w, v1.ErrorStatusInvalidRPCCredentials, nil)
			return
		}
		log.Infof("%v Authorized access for: %v",
			remoteAddr(r), user)
		fn(w, r)
	}
}

func (p *politeia) setVettedStatus(w http.ResponseWriter, r *http.Request) {
	var t v1.SetVettedStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	// Ask backend to update  status
	record, err := p.backend.SetVettedStatus(token,
		convertFrontendStatus(t.Status),
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		// Check for specific errors
		if errors.Is(err, backend.ErrRecordNotFound) {
			log.Infof("%v updateStatus record not "+
				"found: %x", remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusRecordNotFound, nil)
			return
		}
		var serr backend.StateTransitionError
		if errors.As(err, &serr) {
			log.Infof("%v %v %v", remoteAddr(r), t.Token, err)
			p.respondWithUserError(w, v1.ErrorStatusInvalidRecordStatusTransition, nil)
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Set status error code %v: %v",
			remoteAddr(r), errorCode, err)

		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply.
	reply := v1.SetVettedStatusReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertBackendRecord(*record),
	}

	s := convertBackendStatus(record.RecordMetadata.Status)
	log.Infof("Set vetted record status %v: token %v status %v",
		remoteAddr(r), t.Token, v1.RecordStatus[s])

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) setUnvettedStatus(w http.ResponseWriter, r *http.Request) {
	var t v1.SetUnvettedStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	// Ask backend to update unvetted status
	record, err := p.backend.SetUnvettedStatus(token,
		convertFrontendStatus(t.Status),
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		// Check for specific errors
		if errors.Is(err, backend.ErrRecordNotFound) {
			log.Infof("%v updateUnvettedStatus record not "+
				"found: %x", remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusRecordNotFound, nil)
			return
		}
		var serr backend.StateTransitionError
		if errors.As(err, &serr) {
			log.Infof("%v %v %v", remoteAddr(r), t.Token, err)
			p.respondWithUserError(w, v1.ErrorStatusInvalidRecordStatusTransition, nil)
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Set unvetted status error code %v: %v",
			remoteAddr(r), errorCode, err)

		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply.
	reply := v1.SetUnvettedStatusReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertBackendRecord(*record),
	}

	s := convertBackendStatus(record.RecordMetadata.Status)
	log.Infof("Set unvetted record status %v: token %v status %v",
		remoteAddr(r), t.Token, v1.RecordStatus[s])

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) updateVettedMetadata(w http.ResponseWriter, r *http.Request) {
	var t v1.UpdateVettedMetadata
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	log.Infof("Update vetted metadata submitted %v: %x", remoteAddr(r),
		token)

	err = p.backend.UpdateVettedMetadata(token,
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		if errors.Is(err, backend.ErrNoChanges) {
			log.Infof("%v update vetted metadata no changes: %x",
				remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusNoChanges, nil)
			return
		}
		// Check for content error.
		var contentErr backend.ContentVerificationError
		if errors.As(err, &contentErr) {
			log.Infof("%v update vetted metadata content error: %v",
				remoteAddr(r), contentErr)
			p.respondWithUserError(w, contentErr.ErrorCode,
				contentErr.ErrorContext)
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Update vetted metadata error code %v: %v",
			remoteAddr(r), errorCode, err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Reply
	reply := v1.UpdateVettedMetadataReply{
		Response: hex.EncodeToString(response[:]),
	}

	log.Infof("Update vetted metadata %v: token %x", remoteAddr(r), token)

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) updateUnvettedMetadata(w http.ResponseWriter, r *http.Request) {
	var t v1.UpdateUnvettedMetadata
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidToken, nil)
		return
	}

	log.Infof("Update unvetted metadata submitted %v: %x", remoteAddr(r),
		token)

	err = p.backend.UpdateUnvettedMetadata(token,
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		// Reply with error if there were no changes
		if errors.Is(err, backend.ErrNoChanges) {
			log.Infof("%v update unvetted metadata no changes: %x",
				remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusNoChanges, nil)
			return
		}
		// Check for content error.
		var cverr backend.ContentVerificationError
		if errors.As(err, &cverr) {
			log.Infof("%v update unvetted metadata content error: %v",
				remoteAddr(r), cverr)
			p.respondWithUserError(w, cverr.ErrorCode,
				cverr.ErrorContext)
			return
		}
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v update unvetted metadata error code %v: %v",
			remoteAddr(r), errorCode, err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	reply := v1.UpdateUnvettedMetadataReply{
		Response: hex.EncodeToString(response[:]),
	}

	log.Infof("Update unvetted metadata %v: token %x", remoteAddr(r), token)

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) pluginInventory(w http.ResponseWriter, r *http.Request) {
	var pi v1.PluginInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pi); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload,
			nil)
		return
	}

	challenge, err := hex.DecodeString(pi.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Get plugins
	plugins, err := p.backend.GetPlugins()
	if err != nil {
		errorCode := time.Now().Unix()
		log.Errorf("%v get plugins: %v ", remoteAddr(r), err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply
	reply := v1.PluginInventoryReply{
		Plugins:  convertBackendPlugins(plugins),
		Response: hex.EncodeToString(response[:]),
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) pluginCommand(w http.ResponseWriter, r *http.Request) {
	var pc v1.PluginCommand
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pc); err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload,
			nil)
		return
	}

	challenge, err := hex.DecodeString(pc.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	cid, payload, err := p.backend.Plugin(pc.Command, pc.Payload)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v %v: backend plugin failed with "+
			"command:%v payload:%v err:%v", remoteAddr(r),
			errorCode, pc.Command, pc.Payload, err)
		p.respondWithServerError(w, errorCode)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	reply := v1.PluginCommandReply{
		Response:  hex.EncodeToString(response[:]),
		ID:        pc.ID,
		Command:   cid,
		CommandID: pc.CommandID,
		Payload:   payload,
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trace incoming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v %v %v", remoteAddr(r), r.Method, r.URL, r.Proto)
		f(w, r)
	}
}

// closeBody closes the request body after the provided handler is called.
func closeBody(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		r.Body.Close()
	}
}

func (p *politeia) addRoute(method string, route string, handler http.HandlerFunc, perm permission) {
	if perm == permissionAuth {
		handler = p.auth(handler)
	}
	handler = closeBody(logging(handler))

	p.router.StrictSlash(true).HandleFunc(route, handler).Methods(method)
}

func (p *politeia) addRouteV2(method string, route string, handler http.HandlerFunc, perm permission) {
	route = v2.APIRoute + route
	p.addRoute(method, route, handler, perm)
}

func (p *politeia) setupBackendGit(anp *chaincfg.Params) error {
	b, err := gitbe.New(activeNetParams.Params, p.cfg.DataDir,
		p.cfg.DcrtimeHost, "", p.identity, p.cfg.GitTrace, p.cfg.DcrdataHost)
	if err != nil {
		return fmt.Errorf("new gitbe: %v", err)
	}
	p.backend = b

	// Setup mux
	p.router = mux.NewRouter()

	// Not found
	p.router.NotFoundHandler = closeBody(p.handleNotFound)

	// Unprivileged routes
	p.addRoute(http.MethodPost, v1.IdentityRoute, p.getIdentity,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.NewRecordRoute, p.newRecord,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.UpdateUnvettedRoute, p.updateUnvetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.UpdateVettedRoute, p.updateVetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.GetUnvettedRoute, p.getUnvetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.GetVettedRoute, p.getVetted,
		permissionPublic)

	// Routes that require auth
	p.addRoute(http.MethodPost, v1.InventoryRoute, p.inventory,
		permissionAuth)
	p.addRoute(http.MethodPost, v1.SetUnvettedStatusRoute,
		p.setUnvettedStatus, permissionAuth)
	p.addRoute(http.MethodPost, v1.SetVettedStatusRoute,
		p.setVettedStatus, permissionAuth)
	p.addRoute(http.MethodPost, v1.UpdateVettedMetadataRoute,
		p.updateVettedMetadata, permissionAuth)
	p.addRoute(http.MethodPost, v1.UpdateUnvettedMetadataRoute,
		p.updateUnvettedMetadata, permissionAuth)

	// Set plugin routes. Requires auth.
	p.addRoute(http.MethodPost, v1.PluginCommandRoute, p.pluginCommand,
		permissionAuth)
	p.addRoute(http.MethodPost, v1.PluginInventoryRoute, p.pluginInventory,
		permissionAuth)

	return nil
}

func (p *politeia) setupBackendTstore(anp *chaincfg.Params) error {
	b, err := tstorebe.New(p.cfg.HomeDir, p.cfg.DataDir, anp,
		p.cfg.TrillianHost, p.cfg.TrillianSigningKey,
		p.cfg.DBType, p.cfg.DBHost, p.cfg.DBPass, p.cfg.DBEncryptionKey,
		p.cfg.DcrtimeHost, p.cfg.DcrtimeCert)
	if err != nil {
		return fmt.Errorf("new tstorebe: %v", err)
	}
	p.backendv2 = b

	// Setup v1 routes
	p.addRoute(http.MethodPost, v1.IdentityRoute,
		p.getIdentity, permissionPublic)

	// Setup v2 routes
	p.addRouteV2(http.MethodPost, v2.RouteRecordNew,
		p.handleRecordNew, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordEdit,
		p.handleRecordEdit, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordEditMetadata,
		p.handleRecordEditMetadata, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordSetStatus,
		p.handleRecordSetStatus, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordGet,
		p.handleRecordGet, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordGetBatch,
		p.handleRecordGetBatch, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordGetTimestamps,
		p.handleRecordGetTimestamps, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteInventory,
		p.handleInventory, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginWrite,
		p.handlePluginWrite, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginReads,
		p.handlePluginReads, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginInventory,
		p.handlePluginInventory, permissionPublic)

	// Setup plugins
	if len(p.cfg.Plugins) > 0 {
		// Parse plugin settings
		settings := make(map[string][]backendv2.PluginSetting)
		for _, v := range p.cfg.PluginSettings {
			// Plugin setting will be in format: pluginID,key,value
			s := strings.Split(v, ",")
			if len(s) != 3 {
				return fmt.Errorf("failed to parse plugin setting '%v'; format "+
					"should be 'pluginID,key,value'", s)
			}
			var (
				pluginID = s[0]
				key      = s[1]
				value    = s[2]
			)
			ps, ok := settings[pluginID]
			if !ok {
				ps = make([]backendv2.PluginSetting, 0, 16)
			}
			ps = append(ps, backendv2.PluginSetting{
				Key:   key,
				Value: value,
			})

			settings[pluginID] = ps
		}

		// Register plugins
		for _, v := range p.cfg.Plugins {
			// Setup plugin
			ps, ok := settings[v]
			if !ok {
				ps = make([]backendv2.PluginSetting, 0)
			}
			plugin := backendv2.Plugin{
				ID:       v,
				Settings: ps,
				Identity: p.identity,
			}

			// Register plugin
			log.Infof("Register plugin: %v", v)
			err = p.backendv2.PluginRegister(plugin)
			if err != nil {
				return fmt.Errorf("PluginRegister %v: %v", v, err)
			}
		}

		// Setup plugins
		for _, v := range p.backendv2.PluginInventory() {
			log.Infof("Setup plugin: %v", v.ID)
			err = p.backendv2.PluginSetup(v.ID)
			if err != nil {
				return fmt.Errorf("plugin setup %v: %v", v.ID, err)
			}
		}
	}

	return nil
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	cfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Build   : %v", version.BuildMainVersion())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", cfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !util.FileExists(cfg.HTTPSKey) &&
		!util.FileExists(cfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P521(), "politeiad",
			cfg.HTTPSCert, cfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Generate ed25519 identity to save messages, tokens etc.
	if !util.FileExists(cfg.Identity) {
		log.Infof("Generating signing identity...")
		id, err := identity.New()
		if err != nil {
			return err
		}
		err = id.Save(cfg.Identity)
		if err != nil {
			return err
		}
		log.Infof("Signing identity created...")
	}

	// Setup application context.
	p := &politeia{
		cfg: cfg,
	}

	// Load identity.
	p.identity, err = identity.LoadFullIdentity(cfg.Identity)
	if err != nil {
		return err
	}
	log.Infof("Public key: %x", p.identity.Public.Key)

	// Load certs, if there.  If they aren't there assume OS is used to
	// resolve cert validity.
	if len(cfg.DcrtimeCert) != 0 {
		var certPool *x509.CertPool
		if !util.FileExists(cfg.DcrtimeCert) {
			return fmt.Errorf("unable to find dcrtime cert %v",
				cfg.DcrtimeCert)
		}
		dcrtimeCert, err := ioutil.ReadFile(cfg.DcrtimeCert)
		if err != nil {
			return fmt.Errorf("unable to read dcrtime cert %v: %v",
				cfg.DcrtimeCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(dcrtimeCert) {
			return fmt.Errorf("unable to load cert")
		}
	}
	// Setup backend.
	log.Infof("Backend: %v", cfg.Backend)
	switch cfg.Backend {
	case backendGit:
		err := p.setupBackendGit(activeNetParams.Params)
		if err != nil {
			return err
		}
	case backendTstore:
		err := p.setupBackendTstore(activeNetParams.Params)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid backend selected: %v", cfg.Backend)
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range cfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				cfg.HTTPSCert, cfg.HTTPSKey, p.router)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:
	p.backend.Close()

	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
