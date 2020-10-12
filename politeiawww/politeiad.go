// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/util"
)

// pdErrorReply represents the request body that is returned from politeaid
// when an error occurs. PluginID will be populated if this is a plugin error.
type pdErrorReply struct {
	ErrorCode    int
	ErrorContext []string
	Plugin       string
}

// pdError represents a politeiad error.
type pdError struct {
	HTTPCode   int
	ErrorReply pdErrorReply
}

// Error satisfies the error interface.
func (e pdError) Error() string {
	return fmt.Sprintf("error from politeiad: %v %v",
		e.HTTPCode, e.ErrorReply.ErrorCode)
}

// makeRequest makes a politeiad http request to the method and route provided,
// serializing the provided object as the request body. A pdError is returned
// if politeiad does not respond with a 200.
func (p *politeiawww) makeRequest(ctx context.Context, method string, route string, v interface{}) ([]byte, error) {
	var (
		reqBody []byte
		err     error
	)
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := p.cfg.RPCHost + route

	log.Debugf("%v %v", method, fullRoute)

	req, err := http.NewRequestWithContext(ctx, method,
		fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.RPCUser, p.cfg.RPCPass)
	r, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var e pdErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&e); err != nil {
			return nil, fmt.Errorf("status code %v: %v", r.StatusCode, err)
		}

		return nil, pdError{
			HTTPCode:   r.StatusCode,
			ErrorReply: e,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

// newRecord creates a record in politeiad. This route returns the censorship
// record from the new created record.
func (p *politeiawww) newRecord(ctx context.Context, metadata []pd.MetadataStream, files []pd.File) (*pd.CensorshipRecord, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	nr := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  metadata,
		Files:     files,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost, pd.NewRecordRoute, nr)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var nrr pd.NewRecordReply
	err = json.Unmarshal(resBody, &nrr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, nrr.Response)
	if err != nil {
		return nil, err
	}

	return &nrr.CensorshipRecord, nil
}

// updateRecord updates a record in politeiad. This can be used to update
// unvetted or vetted records depending on the route that is provided.
func (p *politeiawww) updateRecord(ctx context.Context, route, token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) (*pd.Record, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	ur := pd.UpdateRecord{
		Token:       token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mdOverwrite,
		FilesAdd:    filesAdd,
		FilesDel:    filesDel,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost, route, ur)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var urr pd.UpdateRecordReply
	err = json.Unmarshal(resBody, &urr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, urr.Response)
	if err != nil {
		return nil, err
	}

	return &urr.Record, nil
}

// updateUnvetted updates an unvetted record in politeiad.
func (p *politeiawww) updateUnvetted(ctx context.Context, token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) (*pd.Record, error) {
	return p.updateRecord(ctx, pd.UpdateUnvettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

// updateVetted updates a vetted record in politeiad.
func (p *politeiawww) updateVetted(ctx context.Context, token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) (*pd.Record, error) {
	return p.updateRecord(ctx, pd.UpdateVettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

// updateUnvettedMetadata updates the metadata of a unvetted record in politeiad.
func (p *politeiawww) updateUnvettedMetadata(ctx context.Context, token string, mdAppend, mdOverwrite []pd.MetadataStream) error {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return err
	}
	uum := pd.UpdateUnvettedMetadata{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.UpdateUnvettedMetadataRoute, uum)
	if err != nil {
		return nil
	}

	// Receive reply
	var uumr pd.UpdateUnvettedMetadataReply
	err = json.Unmarshal(resBody, &uumr)
	if err != nil {
		return err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, uumr.Response)
	if err != nil {
		return err
	}

	return nil
}

// updateVettedMetadata updates the metadata of a vetted record in politeiad.
func (p *politeiawww) updateVettedMetadata(ctx context.Context, token string, mdAppend, mdOverwrite []pd.MetadataStream) error {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return err
	}
	uvm := pd.UpdateVettedMetadata{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.UpdateVettedMetadataRoute, uvm)
	if err != nil {
		return nil
	}

	// Receive reply
	var uvmr pd.UpdateVettedMetadataReply
	err = json.Unmarshal(resBody, &uvmr)
	if err != nil {
		return err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, uvmr.Response)
	if err != nil {
		return err
	}

	return nil
}

// setUnvettedStatus sets the status of a unvetted record in politeiad.
func (p *politeiawww) setUnvettedStatus(ctx context.Context, token string, status pd.RecordStatusT, mdAppend, mdOverwrite []pd.MetadataStream) (*pd.Record, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	sus := pd.SetUnvettedStatus{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		Status:      status,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.SetUnvettedStatusRoute, sus)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var susr pd.SetUnvettedStatusReply
	err = json.Unmarshal(resBody, &susr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, susr.Response)
	if err != nil {
		return nil, err
	}

	return &susr.Record, nil
}

// setVettedStatus sets the status of a vetted record in politeiad.
func (p *politeiawww) setVettedStatus(ctx context.Context, token string, status pd.RecordStatusT, mdAppend, mdOverwrite []pd.MetadataStream) (*pd.Record, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	svs := pd.SetVettedStatus{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		Status:      status,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.SetVettedStatusRoute, svs)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var svsr pd.SetVettedStatusReply
	err = json.Unmarshal(resBody, &svsr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, svsr.Response)
	if err != nil {
		return nil, err
	}

	return &svsr.Record, nil
}

// getUnvetted retrieves an unvetted record from politeiad.
func (p *politeiawww) getUnvetted(ctx context.Context, token, version string) (*pd.Record, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	gu := pd.GetUnvetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost, pd.GetUnvettedRoute, gu)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var gur pd.GetUnvettedReply
	err = json.Unmarshal(resBody, &gur)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, gur.Response)
	if err != nil {
		return nil, err
	}

	return &gur.Record, nil
}

// getUnvettedLatest returns the latest version of the unvetted record for the
// provided token.
func (p *politeiawww) getUnvettedLatest(ctx context.Context, token string) (*pd.Record, error) {
	return p.getUnvetted(ctx, token, "")
}

// getVetted retrieves a vetted record from politeiad.
func (p *politeiawww) getVetted(ctx context.Context, token, version string) (*pd.Record, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	gu := pd.GetVetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.GetVettedRoute, gu)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var gvr pd.GetVettedReply
	err = json.Unmarshal(resBody, &gvr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, gvr.Response)
	if err != nil {
		return nil, err
	}

	return &gvr.Record, nil
}

// getVettedLatest returns the latest version of the vetted record for the
// provided token.
func (p *politeiawww) getVettedLatest(ctx context.Context, token string) (*pd.Record, error) {
	return p.getVetted(ctx, token, "")
}

// pluginInventory requests the plugin inventory from politeiad and returns
// inventoryByStatus retrieves the censorship record tokens filtered by status.
func (p *politeiawww) inventoryByStatus(ctx context.Context) (*pd.InventoryByStatusReply, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	ibs := pd.InventoryByStatus{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.InventoryByStatusRoute, ibs)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var ibsr pd.InventoryByStatusReply
	err = json.Unmarshal(resBody, &ibsr)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, ibsr.Response)
	if err != nil {
		return nil, err
	}

	return &ibsr, nil
}

// pluginInventory requests the plugin inventory from politeiad and returns
// the available plugins slice.
func (p *politeiawww) pluginInventory(ctx context.Context) ([]pd.Plugin, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pi := pd.PluginInventory{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginInventoryRoute, pi)
	if err != nil {
		return nil, err
	}

	// Receive reply
	var pir pd.PluginInventoryReply
	err = json.Unmarshal(resBody, &pir)
	if err != nil {
		return nil, err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pir.Response)
	if err != nil {
		return nil, err
	}

	return pir.Plugins, nil
}

// pluginCommand fires a plugin command on politeiad and returns the reply
// payload.
func (p *politeiawww) pluginCommand(ctx context.Context, pluginID, cmd, payload string) (string, error) {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return "", err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        pluginID,
		Command:   cmd,
		CommandID: "",
		Payload:   payload,
	}

	// Send request
	resBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return "", err
	}

	// Receive reply
	var pcr pd.PluginCommandReply
	err = json.Unmarshal(resBody, &pcr)
	if err != nil {
		return "", err
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pcr.Response)
	if err != nil {
		return "", err
	}

	return pcr.Payload, nil
}
