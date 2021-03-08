// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/util"
)

func (p *politeia) handleRecordNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordNew")

	// Decode request
	var rn v2.RecordNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rn); err != nil {
		respondWithErrorV2(w, r, "handleRecordNew: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(rn.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordNew: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}

	// Create new record
	var (
		metadata = convertMetadataStreamsToBackend(rn.Metadata)
		files    = convertFilesToBackend(rn.Files)
	)
	rc, err := p.backendv2.RecordNew(metadata, files)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordNew: RecordNew: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rnr := v2.RecordNewReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertRecordToV2(*rc),
	}

	util.RespondWithJSON(w, http.StatusOK, rnr)
}

func (p *politeia) handleRecordEdit(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordEdit")

	// Decode request
	var re v2.RecordEdit
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&re); err != nil {
		respondWithErrorV2(w, r, "handleRecordEdit: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(re.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordEdit: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}
	token, err := decodeToken(re.Token)
	if err != nil {
		respondWithErrorV2(w, r, "handleRecordEdit: decode token",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeTokenInvalid,
			})
		return
	}

	// Edit record
	var (
		mdAppend    = convertMetadataStreamsToBackend(re.MDAppend)
		mdOverwrite = convertMetadataStreamsToBackend(re.MDOverwrite)
		filesAdd    = convertFilesToBackend(re.FilesAdd)
	)
	rc, err := p.backendv2.RecordEdit(token, mdAppend,
		mdOverwrite, filesAdd, re.FilesDel)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordEdit: RecordEdit: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rer := v2.RecordEditReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertRecordToV2(*rc),
	}

	util.RespondWithJSON(w, http.StatusOK, rer)
}

func (p *politeia) handleRecordEditMetadata(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordEditMetadata")

	// Decode request
	var re v2.RecordEditMetadata
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&re); err != nil {
		respondWithErrorV2(w, r, "handleRecordEditMetadata: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(re.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordEditMetadata: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}
	token, err := decodeToken(re.Token)
	if err != nil {
		respondWithErrorV2(w, r, "handleRecordEditMetadata: decode token",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeTokenInvalid,
			})
		return
	}

	// Edit record metadata
	var (
		mdAppend    = convertMetadataStreamsToBackend(re.MDAppend)
		mdOverwrite = convertMetadataStreamsToBackend(re.MDOverwrite)
	)
	rc, err := p.backendv2.RecordEditMetadata(token, mdAppend, mdOverwrite)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordEditMetadata: RecordEditMetadata: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rer := v2.RecordEditMetadataReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertRecordToV2(*rc),
	}

	util.RespondWithJSON(w, http.StatusOK, rer)
}

func (p *politeia) handleRecordSetStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordSetStatus")

	// Decode request
	var rss v2.RecordSetStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rss); err != nil {
		respondWithErrorV2(w, r, "handleRecordSetStatus: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(rss.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordSetStatus: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}
	token, err := decodeToken(rss.Token)
	if err != nil {
		respondWithErrorV2(w, r, "handleRecordSetStatus: decode token",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeTokenInvalid,
			})
		return
	}

	// Set record status
	var (
		mdAppend    = convertMetadataStreamsToBackend(rss.MDAppend)
		mdOverwrite = convertMetadataStreamsToBackend(rss.MDOverwrite)
		status      = backendv2.StatusT(rss.Status)
	)
	rc, err := p.backendv2.RecordSetStatus(token, status,
		mdAppend, mdOverwrite)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordSetStatus: RecordSetStatus: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rer := v2.RecordSetStatusReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertRecordToV2(*rc),
	}

	util.RespondWithJSON(w, http.StatusOK, rer)
}

func (p *politeia) handleRecordGet(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordGet")

	// Decode request
	var rg v2.RecordGet
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rg); err != nil {
		respondWithErrorV2(w, r, "handleRecordGet: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(rg.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordGet: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}
	token, err := decodeTokenAnyLength(rg.Token)
	if err != nil {
		respondWithErrorV2(w, r, "handleRecordGet: decode token",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeTokenInvalid,
			})
		return
	}

	// Get record
	rc, err := p.backendv2.RecordGet(token, rg.Version)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordGet: RecordGet: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rgr := v2.RecordGetReply{
		Response: hex.EncodeToString(response[:]),
		Record:   p.convertRecordToV2(*rc),
	}

	util.RespondWithJSON(w, http.StatusOK, rgr)
}

func (p *politeia) handleRecordGetBatch(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordGetBatch")

	// Decode request
	var rgb v2.RecordGetBatch
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rgb); err != nil {
		respondWithErrorV2(w, r, "handleRecordGetBatch: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(rgb.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordGetBatch: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}

	// Get record batch
	reqs := convertRecordRequestsToBackend(rgb.Requests)
	brecords, err := p.backendv2.RecordGetBatch(reqs)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordGet: RecordGetBatch: %v", err)
		return
	}

	// Prepare reply
	records := make(map[string]v2.Record, len(brecords))
	for k, v := range brecords {
		records[k] = p.convertRecordToV2(v)
	}
	response := p.identity.SignMessage(challenge)
	reply := v2.RecordGetBatchReply{
		Response: hex.EncodeToString(response[:]),
		Records:  records,
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeia) handleRecordGetTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordGetTimestamps")

	// Decode request
	var rgt v2.RecordGetTimestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rgt); err != nil {
		respondWithErrorV2(w, r, "handleRecordTimestamps: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(rgt.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleRecordTimestamps: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}
	token, err := decodeTokenAnyLength(rgt.Token)
	if err != nil {
		respondWithErrorV2(w, r, "handleRecordTimestamps: decode token",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeTokenInvalid,
			})
		return
	}

	// Get record timestamps
	rt, err := p.backendv2.RecordTimestamps(token, rgt.Version)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleRecordTimestamps: RecordTimestamps: %v", err)
		return
	}

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	rtr := v2.RecordGetTimestampsReply{
		Response:   hex.EncodeToString(response[:]),
		Timestamps: convertRecordTimestampsToV2(*rt),
	}

	util.RespondWithJSON(w, http.StatusOK, rtr)
}

func (p *politeia) handleInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInventory")

	// Decode request
	var i v2.Inventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		respondWithErrorV2(w, r, "handleInventory: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(i.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handleInventory: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}

	// Get inventory
	var (
		state      = backendv2.StateT(i.State)
		status     = backendv2.StatusT(i.Status)
		pageSize   = v2.InventoryPageSize
		pageNumber = i.Page
	)
	inv, err := p.backendv2.Inventory(state, status, pageSize, pageNumber)
	if err != nil {
		respondWithErrorV2(w, r,
			"handleInventory: Inventory: %v", err)
		return
	}

	// Prepare reply
	unvetted := make(map[string][]string, len(inv.Unvetted))
	for k, v := range inv.Unvetted {
		key := backendv2.Statuses[k]
		unvetted[key] = v
	}
	vetted := make(map[string][]string, len(inv.Vetted))
	for k, v := range inv.Vetted {
		key := backendv2.Statuses[k]
		vetted[key] = v
	}
	response := p.identity.SignMessage(challenge)
	ir := v2.InventoryReply{
		Response: hex.EncodeToString(response[:]),
		Unvetted: unvetted,
		Vetted:   vetted,
	}

	util.RespondWithJSON(w, http.StatusOK, ir)
}

func (p *politeia) handlePluginWrite(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePluginWrite")
	panic("not implemented")
}

func (p *politeia) handlePluginReads(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePluginReads")
	panic("not implemented")
}

func (p *politeia) handlePluginInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePluginInventory")

	// Decode request
	var pi v2.PluginInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pi); err != nil {
		respondWithErrorV2(w, r, "handlePluginInventory: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeRequestPayloadInvalid,
			})
		return
	}
	challenge, err := hex.DecodeString(pi.Challenge)
	if err != nil || len(challenge) != v2.ChallengeSize {
		respondWithErrorV2(w, r, "handlePluginInventory: decode challenge",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeChallengeInvalid,
			})
		return
	}

	// Get plugin inventory
	plugins := p.backendv2.PluginInventory()

	// Prepare reply
	response := p.identity.SignMessage(challenge)
	ir := v2.PluginInventoryReply{
		Response: hex.EncodeToString(response[:]),
		Plugins:  convertPluginsToV2(plugins),
	}

	util.RespondWithJSON(w, http.StatusOK, ir)

}

// decodeToken decodes a v2 token and errors if the token is not the full
// length token.
func decodeToken(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// decodeTokenAnyLength decodes a v2 token. It accepts both the full length
// token and the short token.
func decodeTokenAnyLength(token string) ([]byte, error) {
	return util.TokenDecodeAnyLength(util.TokenTypeTstore, token)
}

func (p *politeia) convertRecordToV2(r backendv2.Record) v2.Record {
	var (
		metadata = convertMetadataStreamsToV2(r.Metadata)
		files    = convertFilesToV2(r.Files)
		rm       = r.RecordMetadata
		sig      = p.identity.SignMessage([]byte(rm.Merkle + rm.Token))
	)
	return v2.Record{
		State:     v2.RecordStateT(rm.State),
		Status:    v2.RecordStatusT(rm.Status),
		Version:   rm.Version,
		Timestamp: rm.Timestamp,
		Metadata:  metadata,
		Files:     files,
		CensorshipRecord: v2.CensorshipRecord{
			Token:     rm.Token,
			Merkle:    rm.Merkle,
			Signature: hex.EncodeToString(sig[:]),
		},
	}
}

func convertMetadataStreamsToBackend(metadata []v2.MetadataStream) []backendv2.MetadataStream {
	ms := make([]backendv2.MetadataStream, 0, len(metadata))
	for _, v := range metadata {
		ms = append(ms, backendv2.MetadataStream{
			PluginID: v.PluginID,
			StreamID: v.StreamID,
			Payload:  v.Payload,
		})
	}
	return ms
}

func convertMetadataStreamsToV2(metadata []backendv2.MetadataStream) []v2.MetadataStream {
	ms := make([]v2.MetadataStream, 0, len(metadata))
	for _, v := range metadata {
		ms = append(ms, v2.MetadataStream{
			PluginID: v.PluginID,
			StreamID: v.StreamID,
			Payload:  v.Payload,
		})
	}
	return ms
}

func convertFilesToBackend(files []v2.File) []backendv2.File {
	fs := make([]backendv2.File, 0, len(files))
	for _, v := range files {
		fs = append(fs, backendv2.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return fs
}

func convertFilesToV2(files []backendv2.File) []v2.File {
	fs := make([]v2.File, 0, len(files))
	for _, v := range files {
		fs = append(fs, v2.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return fs
}

func convertRecordRequestsToBackend(reqs []v2.RecordRequest) []backendv2.RecordRequest {
	r := make([]backendv2.RecordRequest, 0, len(reqs))
	for _, v := range reqs {
		token, err := decodeTokenAnyLength(v.Token)
		if err != nil {
			// Records with errors will not be included in the reply
			log.Debugf("convertRecordRequestsToBackend: decode token: %v", err)
			continue
		}
		r = append(r, backendv2.RecordRequest{
			Token:        token,
			Version:      v.Version,
			Filenames:    v.Filenames,
			OmitAllFiles: v.OmitAllFiles,
		})
	}
	return r
}

func convertProofToV2(p backendv2.Proof) v2.Proof {
	return v2.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV2(t backendv2.Timestamp) v2.Timestamp {
	proofs := make([]v2.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofToV2(v))
	}
	return v2.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

func convertRecordTimestampsToV2(r backendv2.RecordTimestamps) v2.RecordTimestamps {
	metadata := make(map[string]map[uint32]v2.Timestamp, 16)
	for pluginID, v := range r.Metadata {
		timestamps, ok := metadata[pluginID]
		if !ok {
			timestamps = make(map[uint32]v2.Timestamp, 16)
		}
		for streamID, ts := range v {
			timestamps[streamID] = convertTimestampToV2(ts)
		}
		metadata[pluginID] = timestamps
	}
	files := make(map[string]v2.Timestamp, len(r.Files))
	for k, v := range r.Files {
		files[k] = convertTimestampToV2(v)
	}
	return v2.RecordTimestamps{
		RecordMetadata: convertTimestampToV2(r.RecordMetadata),
		Metadata:       metadata,
		Files:          files,
	}
}

func convertPluginSettingToV2(p backendv2.PluginSetting) v2.PluginSetting {
	return v2.PluginSetting{
		Key:   p.Key,
		Value: p.Value,
	}
}

func convertPluginsToV2(bplugins []backendv2.Plugin) []v2.Plugin {
	plugins := make([]v2.Plugin, 0, len(bplugins))
	for _, v := range bplugins {
		settings := make([]v2.PluginSetting, 0, len(v.Settings))
		for _, v := range v.Settings {
			settings = append(settings, convertPluginSettingToV2(v))
		}
		plugins = append(plugins, v2.Plugin{
			ID:       v.ID,
			Settings: settings,
		})
	}
	return plugins
}

func respondWithErrorV2(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		errCode = convertErrorToV2(err)
		ue      v2.UserErrorReply
		ce      backendv2.ContentError
		ste     backendv2.StatusTransitionError
		pe      backendv2.PluginError
	)
	switch {
	case errCode != v2.ErrorCodeInvalid:
		// Backend error
		log.Infof("%v User error: %v %v", util.RemoteAddr(r),
			errCode, v2.ErrorCodes[errCode])
		util.RespondWithJSON(w, http.StatusBadRequest,
			v2.UserErrorReply{
				ErrorCode: errCode,
			})
		return

	case errors.As(err, &ue):
		// Politeiad user error
		m := fmt.Sprintf("%v User error: %v %v", util.RemoteAddr(r),
			ue.ErrorCode, v2.ErrorCodes[ue.ErrorCode])
		if ce.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ce.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest, ue)
		return

	case errors.As(err, &ce):
		// Backend content error
		errCode := convertContentErrorToV2(ce.ErrorCode)
		m := fmt.Sprintf("%v User error: %v %v", util.RemoteAddr(r),
			errCode, v2.ErrorCodes[errCode])
		if ce.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ce.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			v2.UserErrorReply{
				ErrorCode:    errCode,
				ErrorContext: ce.ErrorContext,
			})
		return

	case errors.As(err, &ste):
		// Backend status transition error
		log.Infof("%v User error: %v", util.RemoteAddr(r), ste.Error())
		util.RespondWithJSON(w, http.StatusBadRequest,
			v2.UserErrorReply{
				ErrorCode:    v2.ErrorCodeStatusChangeInvalid,
				ErrorContext: ste.Error(),
			})
		return

	case errors.As(err, &pe):
		// Plugin user error
		m := fmt.Sprintf("%v Plugin error: %v %v",
			util.RemoteAddr(r), pe.PluginID, pe.ErrorCode)
		if pe.ErrorContext != "" {
			m += fmt.Sprintf(": %v", pe.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			v2.PluginErrorReply{
				PluginID:     pe.PluginID,
				ErrorCode:    pe.ErrorCode,
				ErrorContext: pe.ErrorContext,
			})
		return
	}

	// Internal server error. Log it and return a 500.
	t := time.Now().Unix()
	e := fmt.Sprintf(format, err)
	log.Errorf("%v %v %v %v Internal error %v: %v",
		util.RemoteAddr(r), r.Method, r.URL, r.Proto, t, e)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		v2.ServerErrorReply{
			ErrorCode: t,
		})
	return
}

func convertErrorToV2(e error) v2.ErrorCodeT {
	switch e {
	case backendv2.ErrTokenInvalid:
		return v2.ErrorCodeTokenInvalid
	case backendv2.ErrRecordNotFound:
		return v2.ErrorCodeRecordNotFound
	case backendv2.ErrRecordLocked:
		return v2.ErrorCodeRecordLocked
	case backendv2.ErrNoRecordChanges:
		return v2.ErrorCodeNoRecordChanges
	case backendv2.ErrPluginIDInvalid:
		return v2.ErrorCodePluginIDInvalid
	case backendv2.ErrPluginCmdInvalid:
		return v2.ErrorCodePluginCmdInvalid
	}
	return v2.ErrorCodeInvalid
}

func convertContentErrorToV2(e backendv2.ContentErrorCodeT) v2.ErrorCodeT {
	switch e {
	case backendv2.ContentErrorMetadataStreamInvalid:
		return v2.ErrorCodeMetadataStreamInvalid
	case backendv2.ContentErrorMetadataStreamDuplicate:
		return v2.ErrorCodeMetadataStreamDuplicate
	case backendv2.ContentErrorFilesEmpty:
		return v2.ErrorCodeFilesEmpty
	case backendv2.ContentErrorFileNameInvalid:
		return v2.ErrorCodeFileNameInvalid
	case backendv2.ContentErrorFileNameDuplicate:
		return v2.ErrorCodeFileNameDuplicate
	case backendv2.ContentErrorFileDigestInvalid:
		return v2.ErrorCodeFileDigestInvalid
	case backendv2.ContentErrorFilePayloadInvalid:
		return v2.ErrorCodeFilePayloadInvalid
	case backendv2.ContentErrorFileMIMETypeInvalid:
		return v2.ErrorCodeFileMIMETypeInvalid
	case backendv2.ContentErrorFileMIMETypeUnsupported:
		return v2.ErrorCodeFileMIMETypeUnsupported
	}
	return v2.ErrorCodeInvalid
}
