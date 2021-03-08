// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/util"
)

// RecordNew sends a RecordNew command to the politeiad v2 API.
func (c *Client) RecordNew(ctx context.Context, metadata []pdv2.MetadataStream, files []pdv2.File) (*pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rn := pdv2.RecordNew{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  metadata,
		Files:     files,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordNew, rn)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var rnr pdv2.RecordNewReply
	err = json.Unmarshal(resBody, &rnr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, rnr.Response)
	if err != nil {
		return nil, err
	}

	return &rnr.Record, nil
}

// RecordEdit sends a RecordEdit command to the politeiad v2 API.
func (c *Client) RecordEdit(ctx context.Context, token string, mdAppend, mdOverwrite []pdv2.MetadataStream, filesAdd []pdv2.File, filesDel []string) (*pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	re := pdv2.RecordEdit{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
		FilesAdd:    filesAdd,
		FilesDel:    filesDel,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordEdit, re)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var rer pdv2.RecordEditReply
	err = json.Unmarshal(resBody, &rer)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, rer.Response)
	if err != nil {
		return nil, err
	}

	return &rer.Record, nil
}

// RecordEditMetadata sends a RecordEditMetadata command to the politeiad v2
// API.
func (c *Client) RecordEditMetadata(ctx context.Context, token string, mdAppend, mdOverwrite []pdv2.MetadataStream) (*pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rem := pdv2.RecordEditMetadata{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordEditMetadata, rem)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var reply pdv2.RecordEditMetadataReply
	err = json.Unmarshal(resBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return &reply.Record, nil
}

// RecordSetStatus sends a RecordSetStatus command to the politeiad v2 API.
func (c *Client) RecordSetStatus(ctx context.Context, token string, status pdv2.RecordStatusT, mdAppend, mdOverwrite []pdv2.MetadataStream) (*pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rss := pdv2.RecordSetStatus{
		Challenge:   hex.EncodeToString(challenge),
		Token:       token,
		Status:      status,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordSetStatus, rss)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var reply pdv2.RecordSetStatusReply
	err = json.Unmarshal(resBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return &reply.Record, nil
}

// RecordGet sends a RecordGet command to the politeiad v2 API.
func (c *Client) RecordGet(ctx context.Context, token string, version uint32) (*pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rg := pdv2.RecordGet{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordGet, rg)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var rgr pdv2.RecordGetReply
	err = json.Unmarshal(resBody, &rgr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, rgr.Response)
	if err != nil {
		return nil, err
	}

	return &rgr.Record, nil
}

// RecordGetBatch sends a RecordGetBatch command to the politeiad v2 API.
func (c *Client) RecordGetBatch(ctx context.Context, reqs []pdv2.RecordRequest) (map[string]pdv2.Record, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rgb := pdv2.RecordGetBatch{
		Challenge: hex.EncodeToString(challenge),
		Requests:  reqs,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordGetBatch, rgb)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var reply pdv2.RecordGetBatchReply
	err = json.Unmarshal(resBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return reply.Records, nil
}

// RecordGetTimestamps sends a RecordGetTimestamps command to the politeiad v2
// API.
func (c *Client) RecordGetTimestamps(ctx context.Context, token string, version uint32) (*pdv2.RecordTimestamps, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	rgt := pdv2.RecordGetTimestamps{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		Version:   version,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteRecordGetTimestamps, rgt)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var reply pdv2.RecordGetTimestampsReply
	err = json.Unmarshal(resBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return &reply.Timestamps, nil
}

// Inventory sends a Inventory command to the politeiad v2 API.
func (c *Client) Inventory(ctx context.Context, state pdv2.RecordStateT, status pdv2.RecordStatusT, page uint32) (*pdv2.InventoryReply, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	i := pdv2.Inventory{
		Challenge: hex.EncodeToString(challenge),
		State:     state,
		Status:    status,
		Page:      page,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RouteInventory, i)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var ir pdv2.InventoryReply
	err = json.Unmarshal(resBody, &ir)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// PluginWrite sends a PluginWrite command to the politeiad v2 API.
func (c *Client) PluginWrite(ctx context.Context, cmd pdv2.PluginCmd) (string, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return "", err
	}
	pw := pdv2.PluginWrite{
		Challenge: hex.EncodeToString(challenge),
		Cmd:       cmd,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RoutePluginWrite, pw)
	if err != nil {
		return "", err
	}

	// Decode reply
	var pwr pdv2.PluginWriteReply
	err = json.Unmarshal(resBody, &pwr)
	if err != nil {
		return "", err
	}
	err = util.VerifyChallenge(c.pid, challenge, pwr.Response)
	if err != nil {
		return "", err
	}

	return pwr.Payload, nil
}

// PluginReads sends a PluginReads command to the politeiad v2 API.
func (c *Client) PluginReads(ctx context.Context, cmds []pdv2.PluginCmd) ([]pdv2.PluginCmdReply, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pr := pdv2.PluginReads{
		Challenge: hex.EncodeToString(challenge),
		Cmds:      cmds,
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RoutePluginReads, pr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var prr pdv2.PluginReadsReply
	err = json.Unmarshal(resBody, &prr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, prr.Response)
	if err != nil {
		return nil, err
	}

	return prr.Replies, nil
}

// PluginInventory sends a PluginInventory command to the politeiad v2 API.
func (c *Client) PluginInventory(ctx context.Context) ([]pdv2.Plugin, error) {
	// Setup request
	challenge, err := util.Random(pdv2.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pi := pdv2.PluginInventory{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send request
	resBody, err := c.makeReq(ctx, http.MethodPost,
		pdv2.APIRoute, pdv2.RoutePluginInventory, pi)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var pir pdv2.PluginInventoryReply
	err = json.Unmarshal(resBody, &pir)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(c.pid, challenge, pir.Response)
	if err != nil {
		return nil, err
	}

	return pir.Plugins, nil
}

func extractPluginCmdError(pcr pdv2.PluginCmdReply) error {
	switch {
	case pcr.UserError != nil:
		return Error{
			HTTPCode: http.StatusBadRequest,
			ErrorReply: ErrorReply{
				ErrorCode:    int(pcr.UserError.ErrorCode),
				ErrorContext: pcr.UserError.ErrorContext,
			},
		}
	case pcr.PluginError != nil:
		return Error{
			HTTPCode: http.StatusBadRequest,
			ErrorReply: ErrorReply{
				PluginID:     pcr.PluginError.PluginID,
				ErrorCode:    pcr.PluginError.ErrorCode,
				ErrorContext: pcr.PluginError.ErrorContext,
			},
		}
	}
	return nil
}
