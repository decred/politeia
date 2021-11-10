// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

const (
	// Git repo directory names
	payloadDirname      = "payload"
	decredPluginDirname = "plugins/decred"
)

func convertRecordMetadata(gitRepo, token string) (*backend.RecordMetadata, error) {
	return nil, nil
}

func convertFiles(gitRepo, token string) ([]backend.File, error) {
	return nil, nil
}

func convertMetadataStreams(gitRepo, token string) ([]backend.MetadataStream, error) {
	return nil, nil
}

func convertProposalMetadata(gitRepo, token string) (*pi.ProposalMetadata, error) {
	return nil, nil
}

func convertStatusChanges(gitRepo, token string) ([]usermd.StatusChangeMetadata, error) {
	return nil, nil
}

func convertVoteMetadata(gitRepo, token string) (*ticketvote.VoteMetadata, error) {
	return nil, nil
}

func convertAuthDetails(gitRepo, token string) (*ticketvote.AuthDetails, error) {
	return nil, nil
}

func convertVoteDetails(gitRepo, token string) (*ticketvote.VoteDetails, error) {
	return nil, nil
}

func convertCastVotes(gitRepo, token string) ([]ticketvote.CastVoteDetails, error) {
	return nil, nil
}

type commentTypes struct {
	Adds  []comments.CommentAdd
	Dels  []comments.CommentDel
	Votes []comments.CommentVote
}

func convertComments(gitRepo, token string) (*commentTypes, error) {
	return nil, nil
}

// decodeVersion returns the version field from the provided JSON payload. This
// function should only be used when the payload contains a single struct with
// a "version" field.
func decodeVersion(payload []byte) (uint, error) {
	data := make(map[string]interface{}, 32)
	err := json.Unmarshal(payload, &data)
	if err != nil {
		return 0, err
	}
	version := uint(data["version"].(float64))
	if version == 0 {
		return 0, fmt.Errorf("version not found")
	}
	return version, nil
}
