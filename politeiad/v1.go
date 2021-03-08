// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

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
