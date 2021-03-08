// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/util"
)

// NewRecord sends a NewRecord request to the politeiad v1 API.
func (c *Client) NewRecord(ctx context.Context, metadata []pdv1.MetadataStream, files []pdv1.File) (*pdv1.CensorshipRecord, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	nr := pdv1.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  metadata,
		Files:     files,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.NewRecordRoute, nr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var nrr pdv1.NewRecordReply
	err = json.Unmarshal(resBody, &nrr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, nrr.Response)
	if err != nil {
		return nil, err
	}

	return &nrr.CensorshipRecord, nil
}

func (c *Client) updateRecord(ctx context.Context, route, token string, mdAppend, mdOverwrite []pdv1.MetadataStream, filesAdd []pdv1.File, filesDel []string) (*pdv1.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	ur := pdv1.UpdateRecord{
		Token:       token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mdOverwrite,
		FilesAdd:    filesAdd,
		FilesDel:    filesDel,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "", route, ur)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var urr pdv1.UpdateRecordReply
	err = json.Unmarshal(resBody, &urr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, urr.Response)
	if err != nil {
		return nil, err
	}

	return &urr.Record, nil
}

// UpdateUnvetted sends a UpdateRecord request to the unvetted politeiad v1
// API.
func (c *Client) UpdateUnvetted(ctx context.Context, token string, mdAppend, mdOverwrite []pdv1.MetadataStream, filesAdd []pdv1.File, filesDel []string) (*pdv1.Record, error) {
	return c.updateRecord(ctx, pdv1.UpdateUnvettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

// UpdateVetted sends a UpdateRecord request to the vetted politeiad v1 API.
func (c *Client) UpdateVetted(ctx context.Context, token string, mdAppend, mdOverwrite []pdv1.MetadataStream, filesAdd []pdv1.File, filesDel []string) (*pdv1.Record, error) {
	return c.updateRecord(ctx, pdv1.UpdateVettedRoute, token,
		mdAppend, mdOverwrite, filesAdd, filesDel)
}

// UpdateUnvettedMetadata sends a UpdateVettedMetadata request to the politeiad
// v1 API.
func (c *Client) UpdateUnvettedMetadata(ctx context.Context, token string, mdAppend, mdOverwrite []pdv1.MetadataStream) error {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return err
	}
	uum := pdv1.UpdateUnvettedMetadata{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.UpdateUnvettedMetadataRoute, uum)
	if err != nil {
		return nil
	}

	// Decode reply
	var uumr pdv1.UpdateUnvettedMetadataReply
	err = json.Unmarshal(resBody, &uumr)
	if err != nil {
		return err
	}
	err = util.VerifyChallenge(c.pid, challenge, uumr.Response)
	if err != nil {
		return err
	}

	return nil
}

// UpdateVettedMetadata sends a UpdateVettedMetadata request to the politeiad
// v1 API.
func (c *Client) UpdateVettedMetadata(ctx context.Context, token string, mdAppend, mdOverwrite []pdv1.MetadataStream) error {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return err
	}
	uvm := pdv1.UpdateVettedMetadata{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.UpdateVettedMetadataRoute, uvm)
	if err != nil {
		return nil
	}

	// Decode reply
	var uvmr pdv1.UpdateVettedMetadataReply
	err = json.Unmarshal(resBody, &uvmr)
	if err != nil {
		return err
	}
	err = util.VerifyChallenge(c.pid, challenge, uvmr.Response)
	if err != nil {
		return err
	}

	return nil
}

// SetUnvettedStatus sends a SetUnvettedStatus request to the politeiad v1
// API.
func (c *Client) SetUnvettedStatus(ctx context.Context, token string, status pdv1.RecordStatusT, mdAppend, mdOverwrite []pdv1.MetadataStream) (*pdv1.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	sus := pdv1.SetUnvettedStatus{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		Status:      status,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.SetUnvettedStatusRoute, sus)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var susr pdv1.SetUnvettedStatusReply
	err = json.Unmarshal(resBody, &susr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, susr.Response)
	if err != nil {
		return nil, err
	}

	return &susr.Record, nil
}

// SetVettedStatus sends a SetVettedStatus request to the politeiad v1 API.
func (c *Client) SetVettedStatus(ctx context.Context, token string, status pdv1.RecordStatusT, mdAppend, mdOverwrite []pdv1.MetadataStream) (*pdv1.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	svs := pdv1.SetVettedStatus{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		Status:      status,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.SetVettedStatusRoute, svs)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var svsr pdv1.SetVettedStatusReply
	err = json.Unmarshal(resBody, &svsr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, svsr.Response)
	if err != nil {
		return nil, err
	}

	return &svsr.Record, nil
}

// GetUnvetted sends a GetUnvetted request to the politeiad v1 API.
func (c *Client) GetUnvetted(ctx context.Context, token, version string) (*pdv1.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	gu := pdv1.GetUnvetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.GetUnvettedRoute, gu)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var gur pdv1.GetUnvettedReply
	err = json.Unmarshal(resBody, &gur)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, gur.Response)
	if err != nil {
		return nil, err
	}

	return &gur.Record, nil
}

// GetVetted sends a GetVetted request to the politeiad v1 API.
func (c *Client) GetVetted(ctx context.Context, token, version string) (*pdv1.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	gv := pdv1.GetVetted{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.GetVettedRoute, gv)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var gvr pdv1.GetVettedReply
	err = json.Unmarshal(resBody, &gvr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, gvr.Response)
	if err != nil {
		return nil, err
	}

	return &gvr.Record, nil
}

// PluginCommand sends a PluginCommand request to the politeiad v1 API.
func (c *Client) PluginCommand(ctx context.Context, pluginID, cmd, payload string) (string, error) {
	// Setup request
	challenge, err := util.Random(pdv1.ChallengeSize)
	if err != nil {
		return "", err
	}
	pc := pdv1.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        pluginID,
		Command:   cmd,
		CommandID: cmd,
		Payload:   payload,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost, "",
		pdv1.PluginCommandRoute, pc)
	if err != nil {
		return "", err
	}

	// Decode reply
	var pcr pdv1.PluginCommandReply
	err = json.Unmarshal(resBody, &pcr)
	if err != nil {
		return "", err
	}
	err = util.VerifyChallenge(c.pid, challenge, pcr.Response)
	if err != nil {
		return "", err
	}

	return pcr.Payload, nil
}
