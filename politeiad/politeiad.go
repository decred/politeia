// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/thi4go/politeia/decredplugin"
	v1 "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/thi4go/politeia/politeiad/backend"
	"github.com/thi4go/politeia/politeiad/backend/gitbe"
	"github.com/thi4go/politeia/politeiad/cache"
	"github.com/thi4go/politeia/politeiad/cache/cachestub"
	"github.com/thi4go/politeia/politeiad/cache/cockroachdb"
	"github.com/thi4go/politeia/util"
	"github.com/thi4go/politeia/util/version"
	"github.com/gorilla/mux"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionAuth
)

// politeia application context.
type politeia struct {
	backend  backend.Backend
	cache    cache.Cache
	cfg      *config
	router   *mux.Router
	identity *identity.FullIdentity
	plugins  map[string]v1.Plugin
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

func convertBackendPlugin(bpi backend.Plugin) v1.Plugin {
	p := v1.Plugin{
		ID: bpi.ID,
	}
	for _, v := range bpi.Settings {
		p.Settings = append(p.Settings, convertBackendPluginSetting(v))
	}

	return p
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

func convertBackendStatusToCache(status backend.MDStatusT) cache.RecordStatusT {
	s := cache.RecordStatusInvalid
	switch status {
	case backend.MDStatusInvalid:
		s = cache.RecordStatusInvalid
	case backend.MDStatusUnvetted:
		s = cache.RecordStatusNotReviewed
	case backend.MDStatusVetted:
		s = cache.RecordStatusPublic
	case backend.MDStatusCensored:
		s = cache.RecordStatusCensored
	case backend.MDStatusIterationUnvetted:
		s = cache.RecordStatusUnreviewedChanges
	case backend.MDStatusArchived:
		s = cache.RecordStatusArchived
	}
	return s
}

func convertBackendPluginToCache(p backend.Plugin) cache.Plugin {
	settings := make([]cache.PluginSetting, 0, len(p.Settings))
	for _, s := range p.Settings {
		settings = append(settings, cache.PluginSetting{
			Key:   s.Key,
			Value: s.Value,
		})
	}
	return cache.Plugin{
		ID:       p.ID,
		Version:  p.Version,
		Settings: settings,
	}
}

func convertMDStreamsToCache(ms []backend.MetadataStream) []cache.MetadataStream {
	m := make([]cache.MetadataStream, 0, len(ms))
	for _, v := range ms {
		m = append(m, cache.MetadataStream{
			ID:      v.ID,
			Payload: v.Payload,
		})
	}
	return m
}

func (p *politeia) convertBackendRecordToCache(r backend.Record) cache.Record {
	msg := []byte(r.RecordMetadata.Merkle + r.RecordMetadata.Token)
	signature := p.identity.SignMessage(msg)
	cr := cache.CensorshipRecord{
		Token:     r.RecordMetadata.Token,
		Merkle:    r.RecordMetadata.Merkle,
		Signature: hex.EncodeToString(signature[:]),
	}

	files := make([]cache.File, 0, len(r.Files))
	for _, f := range r.Files {
		files = append(files,
			cache.File{
				Name:    f.Name,
				MIME:    f.MIME,
				Digest:  f.Digest,
				Payload: f.Payload,
			})
	}

	return cache.Record{
		Version:          r.Version,
		Status:           convertBackendStatusToCache(r.RecordMetadata.Status),
		Timestamp:        r.RecordMetadata.Timestamp,
		CensorshipRecord: cr,
		Metadata:         convertMDStreamsToCache(r.Metadata),
		Files:            files,
	}
}

func (p *politeia) respondWithUserError(w http.ResponseWriter,
	errorCode v1.ErrorStatusT, errorContext []string) {
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
		log.Errorf("%v newRecord: invalid challenge", remoteAddr(r))
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	log.Infof("New record submitted %v", remoteAddr(r))

	md := convertFrontendMetadataStream(t.Metadata)
	files := convertFrontendFiles(t.Files)
	rm, err := p.backend.New(md, files)
	if err != nil {
		// Check for content error.
		if contentErr, ok := err.(backend.ContentVerificationError); ok {
			log.Errorf("%v New record content error: %v",
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

	// Update cache.
	record := p.convertBackendRecordToCache(backend.Record{
		RecordMetadata: *rm,
		Version:        "1",
		Metadata:       md,
		Files:          files,
	})
	err = p.cache.NewRecord(record)
	if err != nil {
		log.Criticalf("Cache new record failed %v: %v",
			record.CensorshipRecord.Token, err)
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
		log.Errorf("%v update %v record: invalid challenge",
			remoteAddr(r), cmd)
		p.respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	// Validate token
	token, err := util.ConvertStringToken(t.Token)
	if err != nil {
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload,
			nil)
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
		if err == backend.ErrRecordFound {
			log.Errorf("%v update %v record found: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusRecordFound,
				nil)
			return
		}
		if err == backend.ErrRecordNotFound {
			log.Errorf("%v update %v record not found: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusRecordFound,
				nil)
			return
		}
		if err == backend.ErrNoChanges {
			log.Errorf("%v update %v record no changes: %x",
				remoteAddr(r), cmd, token)
			p.respondWithUserError(w, v1.ErrorStatusNoChanges, nil)
			return
		}
		// Check for content error.
		if contentErr, ok := err.(backend.ContentVerificationError); ok {
			log.Errorf("%v update %v record content error: %v",
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

	// Update cache.
	cr := p.convertBackendRecordToCache(*record)
	if vetted {
		// Create a new cache entry for new versions.
		err := p.cache.NewRecord(cr)
		if err != nil {
			log.Criticalf("Cache update vetted failed %v: %v",
				cr.CensorshipRecord.Token, err)
		}
	} else {
		// Update existing cache entry for new iterations that are not
		// new versions.
		err = p.cache.UpdateRecord(cr)
		if err != nil {
			log.Criticalf("Cache update unvetted failed %v: %v",
				cr.CensorshipRecord.Token, err)
		}
	}

	// Prepare reply.
	response := p.identity.SignMessage(challenge)
	reply := v1.UpdateRecordReply{
		Response: hex.EncodeToString(response[:]),
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

func (p *politeia) updateReadme(w http.ResponseWriter, r *http.Request) {
	var t v1.UpdateReadme
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

	reply := v1.UpdateReadmeReply{
		Response: hex.EncodeToString(response[:]),
	}

	err = p.backend.UpdateReadme(t.Content)
	if err != nil {
		errorCode := time.Now().Unix()
		log.Errorf("Error updating readme: %v", err)
		p.respondWithServerError(w, errorCode)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
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
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetUnvetted(token)
	if err == backend.ErrRecordNotFound {
		reply.Record.Status = v1.RecordStatusNotFound
		log.Errorf("Get unvetted record %v: token %v not found",
			remoteAddr(r), t.Token)
	} else if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Get unvetted record error code %v: %v",
			remoteAddr(r), errorCode, err)

		p.respondWithServerError(w, errorCode)
		return
	} else {
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

		log.Infof("Get unvetted record %v: token %v", remoteAddr(r),
			t.Token)
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
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Ask backend about the censorship token.
	bpr, err := p.backend.GetVetted(token, t.Version)
	if err == backend.ErrRecordNotFound {
		reply.Record.Status = v1.RecordStatusNotFound
		log.Errorf("Get vetted record %v: token %v not found",
			remoteAddr(r), t.Token)
	} else if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v Get vetted record error code %v: %v",
			remoteAddr(r), errorCode, err)

		p.respondWithServerError(w, errorCode)
		return
	} else {
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
		log.Infof("Get vetted record %v: token %v", remoteAddr(r),
			t.Token)
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
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
	prs, brs, err := p.backend.Inventory(i.VettedCount, i.BranchesCount,
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
			log.Errorf("%v Unauthorized access for: %v",
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
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Ask backend to update  status
	record, err := p.backend.SetVettedStatus(token,
		convertFrontendStatus(t.Status),
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		// Check for specific errors
		if err == backend.ErrRecordNotFound {
			log.Errorf("%v updateStatus record not "+
				"found: %x", remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusRecordFound,
				nil)
			return
		}
		if _, ok := err.(backend.StateTransitionError); ok {
			log.Errorf("%v %v %v", remoteAddr(r), t.Token, err)
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

	// Update cache.
	cr := p.convertBackendRecordToCache(*record)
	err = p.cache.UpdateRecordStatus(cr.CensorshipRecord.Token,
		cr.Version, cr.Status, cr.Timestamp, cr.Metadata)
	if err != nil {
		log.Criticalf("Cache set vetted status failed %v: %v",
			cr.CensorshipRecord.Token, err)
	}

	// Prepare reply.
	reply := v1.SetVettedStatusReply{
		Response: hex.EncodeToString(response[:]),
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
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Ask backend to update unvetted status
	record, err := p.backend.SetUnvettedStatus(token,
		convertFrontendStatus(t.Status),
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		// Check for specific errors
		if err == backend.ErrRecordNotFound {
			log.Errorf("%v updateUnvettedStatus record not "+
				"found: %x", remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusRecordFound,
				nil)
			return
		}
		if _, ok := err.(backend.StateTransitionError); ok {
			log.Errorf("%v %v %v", remoteAddr(r), t.Token, err)
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

	// Update cache.
	cr := p.convertBackendRecordToCache(*record)
	err = p.cache.UpdateRecordStatus(cr.CensorshipRecord.Token,
		cr.Version, cr.Status, cr.Timestamp, cr.Metadata)
	if err != nil {
		log.Criticalf("Cache set unvetted status failed %v: %v",
			cr.CensorshipRecord.Token, err)
	}

	// Prepare reply.
	reply := v1.SetUnvettedStatusReply{
		Response: hex.EncodeToString(response[:]),
	}

	s := convertBackendStatus(record.RecordMetadata.Status)
	log.Infof("Set unvetted record status %v: token %v status %v",
		remoteAddr(r), t.Token, v1.RecordStatus[s])

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) cacheUpdateVettedMetadata(token []byte) error {
	r, err := p.backend.GetVetted(token, "")
	if err != nil {
		return fmt.Errorf("get vetted: %v", err)
	}

	m := convertMDStreamsToCache(r.Metadata)
	t := hex.EncodeToString(token)
	return p.cache.UpdateRecordMetadata(t, m)
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
		p.respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	log.Infof("Update vetted metadata submitted %v: %x", remoteAddr(r),
		token)

	err = p.backend.UpdateVettedMetadata(token,
		convertFrontendMetadataStream(t.MDAppend),
		convertFrontendMetadataStream(t.MDOverwrite))
	if err != nil {
		if err == backend.ErrNoChanges {
			log.Errorf("%v update vetted metadata no changes: %x",
				remoteAddr(r), token)
			p.respondWithUserError(w, v1.ErrorStatusNoChanges, nil)
			return
		}
		// Check for content error.
		if contentErr, ok := err.(backend.ContentVerificationError); ok {
			log.Errorf("%v update vetted metadata content error: %v",
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

	// Update the cache
	err = p.cacheUpdateVettedMetadata(token)
	if err != nil {
		log.Criticalf("Cache updated vetted metadata failed %x: %v",
			token, err)
	}

	// Reply
	reply := v1.UpdateVettedMetadataReply{
		Response: hex.EncodeToString(response[:]),
	}

	log.Infof("Update vetted metadata %v: token %x", remoteAddr(r), token)

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

	reply := v1.PluginInventoryReply{
		Response: hex.EncodeToString(response[:]),
	}

	for _, v := range p.plugins {
		reply.Plugins = append(reply.Plugins, v)
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

	// Send plugin command to cache
	_, err = p.cache.PluginExec(cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        pc.Command,
		CommandPayload: pc.Payload,
		ReplyPayload:   payload,
	})
	if err != nil {
		log.Criticalf("Cache plugin exec failed: command:%v"+
			"commandPayload:%v replyPayload:%v error:%v",
			pc.Command, pc.Payload, payload, err)
	}

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

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Build Version: %v", version.BuildMainVersion())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Issue a warning if pi was builded locally and does not
	// have the main module info available.
	if version.BuildMainVersion() == "(devel)" {
		log.Warnf("Warning: no build information available")
	}

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !util.FileExists(loadedCfg.HTTPSKey) &&
		!util.FileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P521(), "politeiad",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Generate ed25519 identity to save messages, tokens etc.
	if !util.FileExists(loadedCfg.Identity) {
		log.Infof("Generating signing identity...")
		id, err := identity.New()
		if err != nil {
			return err
		}
		err = id.Save(loadedCfg.Identity)
		if err != nil {
			return err
		}
		log.Infof("Signing identity created...")
	}

	// Setup application context.
	p := &politeia{
		cfg:     loadedCfg,
		plugins: make(map[string]v1.Plugin),
		cache:   cachestub.New(),
	}

	// Load identity.
	p.identity, err = identity.LoadFullIdentity(loadedCfg.Identity)
	if err != nil {
		return err
	}
	log.Infof("Public key: %x", p.identity.Public.Key)

	// Load certs, if there.  If they aren't there assume OS is used to
	// resolve cert validity.
	if len(loadedCfg.DcrtimeCert) != 0 {
		var certPool *x509.CertPool
		if !util.FileExists(loadedCfg.DcrtimeCert) {
			return fmt.Errorf("unable to find dcrtime cert %v",
				loadedCfg.DcrtimeCert)
		}
		dcrtimeCert, err := ioutil.ReadFile(loadedCfg.DcrtimeCert)
		if err != nil {
			return fmt.Errorf("unable to read dcrtime cert %v: %v",
				loadedCfg.DcrtimeCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(dcrtimeCert) {
			return fmt.Errorf("unable to load cert")
		}
	}

	// Setup backend.
	gitbe.UseLogger(gitbeLog)
	b, err := gitbe.New(activeNetParams.Params, loadedCfg.DataDir,
		loadedCfg.DcrtimeHost, "", p.identity, loadedCfg.GitTrace,
		loadedCfg.DcrdataHost)
	if err != nil {
		return err
	}
	p.backend = b

	// Setup cache
	if p.cfg.EnableCache {
		// Create a new cache context
		cockroachdb.UseLogger(cockroachdbLog)
		net := filepath.Base(p.cfg.DataDir)
		db, err := cockroachdb.New(cockroachdb.UserPoliteiad, p.cfg.CacheHost,
			net, p.cfg.CacheRootCert, p.cfg.CacheCert, p.cfg.CacheKey)
		if err == cache.ErrNoVersionRecord || err == cache.ErrWrongVersion {
			// The cache version record was either not found or
			// is the wrong version which means that the cache
			// needs to be built/rebuilt.
			p.cfg.BuildCache = true
		} else if err != nil {
			return fmt.Errorf("cockroachdb new: %v", err)
		}
		p.cache = db

		// Setup the cache tables
		err = p.cache.Setup()
		if err != nil {
			return fmt.Errorf("cache setup: %v", err)
		}
	}

	// Setup mux
	p.router = mux.NewRouter()

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
	p.addRoute(http.MethodPost, v1.UpdateReadmeRoute,
		p.updateReadme, permissionAuth)

	// Setup plugins
	plugins, err := p.backend.GetPlugins()
	if err != nil {
		return err
	}
	if len(plugins) > 0 {
		// Set plugin routes. Requires auth.
		p.addRoute(http.MethodPost, v1.PluginCommandRoute, p.pluginCommand,
			permissionAuth)
		p.addRoute(http.MethodPost, v1.PluginInventoryRoute, p.pluginInventory,
			permissionAuth)

		for _, v := range plugins {
			// make sure we only have lowercase names
			if backend.PluginRE.FindString(v.ID) != v.ID {
				return fmt.Errorf("invalid plugin id: %v", v.ID)
			}
			if _, found := p.plugins[v.ID]; found {
				return fmt.Errorf("duplicate plugin: %v", v.ID)
			}
			p.plugins[v.ID] = convertBackendPlugin(v)

			// Register plugin with the cache
			cp := convertBackendPluginToCache(v)
			err := p.cache.RegisterPlugin(cp)
			if err == cache.ErrNoVersionRecord || err == cache.ErrWrongVersion {
				// The cache plugin version record was either not found
				// or it is the wrong version which means that the cache
				// needs to be built/rebuilt.
				p.cfg.BuildCache = true
			} else if err != nil {
				return fmt.Errorf("cache register plugin '%v': %v",
					cp.ID, err)
			}

			// Setup the cache plugin tables
			err = p.cache.PluginSetup(cp.ID)
			if err != nil {
				return fmt.Errorf("cache plugin setup '%v': %v",
					cp.ID, err)
			}

			log.Infof("Registered plugin: %v", v.ID)
		}
	}

	// Build the cache
	if p.cfg.BuildCache {
		// Fetch all versions of all records from the inventory and
		// use them to build the cache.
		vetted, unvetted, err := p.backend.Inventory(0, 0, true, true)
		if err != nil {
			return fmt.Errorf("backend inventory: %v", err)
		}

		inv := make([]cache.Record, 0, len(vetted)+len(unvetted))
		for _, r := range vetted {
			inv = append(inv, p.convertBackendRecordToCache(r))
		}
		for _, r := range unvetted {
			inv = append(inv, p.convertBackendRecordToCache(r))
		}

		// Build the cache
		err = p.cache.Build(inv)
		if err != nil {
			return fmt.Errorf("build cache: %v", err)
		}

		// Build the cache for plugins
		// XXX when we create an interface for plugins we need to
		// rethink how we're building the plugin caches. Reading the
		// entire plugin inventory into memory is only a temporary
		// solution.
		for _, v := range p.plugins {
			var cmd string
			for _, s := range v.Settings {
				if s.Key == "inventory" {
					cmd = s.Value
				}
			}
			if cmd == "" {
				continue
			}

			// Fetch plugin inventory
			_, payload, err := p.backend.Plugin(cmd, "")
			if err != nil {
				log.Errorf("Failed to get plugin data to build cache "+
					"plugin:%v command:%v error:%v", v.ID, cmd, err)
			}

			// Build plugin cache
			err = p.cache.PluginBuild(v.ID, payload)
			if err != nil {
				return fmt.Errorf("plugin '%v' build cache: %v", v.ID, err)
			}
		}
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				p.router)
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
	p.cache.Close()
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
