// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/util"
)

// TODO politeiad API changes that are needed
// -The politeiad UpdateRecordReply is suppose to return the censorship record
//  but it doesn't.
// -Add an updateUnvettedMetadata route. This has been added to the politeiad
//  Backend interface, but a corresponding route has not been added yet.
// -Add a InventoryByStatus route. This has been added to the politeiad
//  Backend interface, but a corresponding route has not been added yet.
//
// TODO add functions to this file for:
// -setUnvettedStatus
// -setVettedStatus
// -updateUnvettedMetadata
// -updatedVettedMetadata
// -plugin

// pdErrorReply represents the request body that is returned from politeaid
// when an error occurs. PluginID will be populated if this is a plugin error.
type pdErrorReply struct {
	ErrorCode    int
	ErrorContext []string
	PluginID     string
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
func (p *politeiawww) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody []byte
		err         error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := p.cfg.RPCHost + route

	if p.client == nil {
		p.client, err = util.NewClient(false, p.cfg.RPCCert)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
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
			return nil, err
		}

		return nil, pdError{
			HTTPCode:   r.StatusCode,
			ErrorReply: e,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

func (p *politeiawww) newRecord(metadata []pd.MetadataStream, files []pd.File) (*pd.CensorshipRecord, error) {
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
	resBody, err := p.makeRequest(http.MethodPost, pd.NewRecordRoute, nr)
	if err != nil {
		return nil, err
	}

	var nrr pd.NewRecordReply
	err = json.Unmarshal(resBody, &nrr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, nrr.Response)
	if err != nil {
		return nil, err
	}

	return &nrr.CensorshipRecord, nil
}

// updateRecord updates a record in politeiad. This can be used to update
// unvetted or vetted records depending on the route that is provided.
func (p *politeiawww) updateRecord(route, token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) error {
	// Setup request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return err
	}
	ur := pd.UpdateRecord{
		Token:       token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mdOverwrite,
		FilesAdd:    filesAdd,
		FilesDel:    filesDel,
	}

	// Send request
	resBody, err := p.makeRequest(http.MethodPost, route, ur)
	if err != nil {
		return nil
	}
	var urr pd.UpdateRecordReply
	err = json.Unmarshal(resBody, &urr)
	if err != nil {
		return err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, urr.Response)
	if err != nil {
		return err
	}

	return nil
}

// updateUnvetted updates an unvetted record in politeiad.
func (p *politeiawww) updateUnvetted(token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) error {
	return p.updateRecord(pd.UpdateUnvettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

// updateVetted updates a vetted record in politeiad.
func (p *politeiawww) updateVetted(token string, mdAppend, mdOverwrite []pd.MetadataStream, filesAdd []pd.File, filesDel []string) error {
	return p.updateRecord(pd.UpdateVettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

func (p *politeiawww) setUnvettedStatus(token string, status pd.RecordStatusT, mdAppend, mdOverwrite []pd.MetadataStream) error {

	return nil
}

func (p *politeiawww) setVettedStatus(token string, status pd.RecordStatusT, mdAppend, mdOverwrite []pd.MetadataStream) error {

	return nil
}

// getUnvetted retrieves an unvetted record from politeiad.
func (p *politeiawww) getUnvetted(token, version string) (*pd.Record, error) {
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
	resBody, err := p.makeRequest(http.MethodPost, pd.GetUnvettedRoute, gu)
	if err != nil {
		return nil, err
	}
	var gur pd.GetUnvettedReply
	err = json.Unmarshal(resBody, &gur)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, gur.Response)
	if err != nil {
		return nil, err
	}

	return &gur.Record, nil
}

// getUnvettedLatest returns the latest version of the unvetted record for the
// provided token.
func (p *politeiawww) getUnvettedLatest(token string) (*pd.Record, error) {
	return p.getUnvetted(token, "")
}

// getVetted retrieves a vetted record from politeiad.
func (p *politeiawww) getVetted(token, version string) (*pd.Record, error) {
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
	resBody, err := p.makeRequest(http.MethodPost, pd.GetVettedRoute, gu)
	if err != nil {
		return nil, err
	}
	var gvr pd.GetVettedReply
	err = json.Unmarshal(resBody, &gvr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, gvr.Response)
	if err != nil {
		return nil, err
	}

	return &gvr.Record, nil
}

// getVettedLatest returns the latest version of the vvetted record for the
// provided token.
func (p *politeiawww) getVettedLatest(token string) (*pd.Record, error) {
	return p.getVetted(token, "")
}
