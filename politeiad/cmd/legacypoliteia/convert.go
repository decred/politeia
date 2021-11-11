// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// convertRecordMetadata reads the git backend RecordMetadata from disk for
// the provided proposal and converts it to a tstore backend RecordMetadata.
func convertRecordMetadata(proposalDir string) (*backend.RecordMetadata, error) {
	// Read the git backend record metadata from disk
	fp := recordMetadataPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var r gitbe.RecordMetadata
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}

	// The version number can be found in the proposal
	// file path. It is the last directory in the path.
	v := filepath.Base(proposalDir)
	version, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}

	return &backend.RecordMetadata{
		Token:     r.Token,
		Version:   uint32(version),
		Iteration: uint32(r.Iteration),
		State:     backend.StateVetted,
		Status:    convertMDStatus(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.Merkle,
	}, nil
}

func recordMetadataPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordMetadataFilename)
}

func convertMDStatus(s gitbe.MDStatusT) backend.StatusT {
	switch s {
	case gitbe.MDStatusUnvetted:
		return backend.StatusUnreviewed
	case gitbe.MDStatusVetted:
		return backend.StatusPublic
	case gitbe.MDStatusCensored:
		return backend.StatusCensored
	case gitbe.MDStatusIterationUnvetted:
		return backend.StatusUnreviewed
	case gitbe.MDStatusArchived:
		return backend.StatusArchived
	default:
		panic(fmt.Sprintf("invalid md status %v", s))
	}
}

func convertFiles(proposalDir string) ([]backend.File, error) {
	return nil, nil
}

func convertMetadataStreams(proposalDir string) ([]backend.MetadataStream, error) {
	return nil, nil
}

func convertProposalMetadata(proposalDir string) (*pi.ProposalMetadata, error) {
	return nil, nil
}

func convertStatusChanges(proposalDir string) ([]usermd.StatusChangeMetadata, error) {
	return nil, nil
}

func convertVoteMetadata(proposalDir string) (*ticketvote.VoteMetadata, error) {
	return nil, nil
}

func convertAuthDetails(proposalDir string) (*ticketvote.AuthDetails, error) {
	return nil, nil
}

func convertVoteDetails(proposalDir string) (*ticketvote.VoteDetails, error) {
	return nil, nil
}

func convertCastVotes(proposalDir string) ([]ticketvote.CastVoteDetails, error) {
	return nil, nil
}

type commentTypes struct {
	Adds  []comments.CommentAdd
	Dels  []comments.CommentDel
	Votes []comments.CommentVote
}

func convertComments(proposalDir string) (*commentTypes, error) {
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
