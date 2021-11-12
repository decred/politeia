// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
)

// convertRecordMetadata reads the git backend RecordMetadata from disk for
// the provided proposal and converts it to a tstore backend RecordMetadata.
func convertRecordMetadata(proposalDir string) (*backend.RecordMetadata, error) {
	fmt.Printf("  RecordMetadata\n")

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

	// Build record metadata
	rm := backend.RecordMetadata{
		Token:     r.Token,
		Version:   uint32(version),
		Iteration: uint32(r.Iteration),
		State:     backend.StateVetted,
		Status:    convertMDStatus(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.Merkle,
	}

	fmt.Printf("    Token  : %v\n", rm.Token)
	fmt.Printf("    Version: %v\n", rm.Version)
	fmt.Printf("    Status : %v\n", backend.Statuses[rm.Status])

	return &rm, nil
}

// convertFiles reads all of the git backend proposal index file and image
// attachments from disk for the provided proposal and converts them to tstore
// backend files.
func convertFiles(proposalDir string) ([]backend.File, error) {
	fmt.Printf("  Files\n")

	files := make([]backend.File, 0, 64)

	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	files = append(files, newFile(b, pi.FileNameIndexFile))

	fmt.Printf("    %v\n", pi.FileNameIndexFile)

	// Read any image attachments from disk
	attachments, err := proposalAttachmentFilenames(proposalDir)
	if err != nil {
		return nil, err
	}
	for _, fn := range attachments {
		fp := attachmentFilePath(proposalDir, fn)
		b, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, err
		}

		files = append(files, newFile(b, fn))

		fmt.Printf("    %v\n", fn)
	}

	return files, nil
}

// convertProposalMetadata reads the git backend data from disk that is
// required to build a pi plugin ProposalMetadata structure, then returns the
// ProposalMetadata.
func convertProposalMetadata(proposalDir string) (*pi.ProposalMetadata, error) {
	fmt.Printf("  Proposal metadata\n")

	// The only data we need to pull from the legacy
	// proposal is the proposal name. The name will
	// always be the first line of the proposal index
	// file.
	name, err := parseProposalName(proposalDir)
	if err != nil {
		return nil, err
	}

	fmt.Printf("    Name: %v\n", name)

	// Get the legacy token from the proposal
	// directory path.
	token, ok := gitProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}

	return &pi.ProposalMetadata{
		Name:        name,
		Amount:      0,
		StartDate:   0,
		EndDate:     0,
		Domain:      "",
		LegacyToken: token,
	}, nil
}

// TODO skip for now. Add when we're ready to add RFP proposals and
// submissions.
func convertVoteMetadata(proposalDir string) (*ticketvote.VoteMetadata, error) {
	return nil, nil
}

func convertUserMetadata(proposalDir string) (*usermd.UserMetadata, error) {
	fmt.Printf("  User metadata\n")

	// Read the proposal general mdstream from disk
	fp := proposalGeneralPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// We can decode both the v1 and v2 proposal general
	// metadata stream into the ProposalGeneralV2 struct
	// since the fields we need from it are present in
	// both versions.
	var p gitbe.ProposalGeneralV2
	err = json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}

	fmt.Printf("    PublicKey: %v\n", p.PublicKey)
	fmt.Printf("    Signature: %v\n", p.Signature)

	return &usermd.UserMetadata{
		UserID:    "", // TODO pull user ID from prod using pubkey
		PublicKey: p.PublicKey,
		Signature: p.Signature,
	}, nil
}

func convertStatusChanges(proposalDir string) ([]usermd.StatusChangeMetadata, error) {
	fmt.Printf("  Status changes\n")

	// Read the status changes mdstream from disk
	fp := statusChangesPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// Parse the token and version from the proposal dir path
	token, ok := gitProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}
	version, err := proposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// The git backend v1 status change struct does not have the
	// signature included. This is the only difference between
	// v1 and v2, so we decode all of them into the v2 structure.
	var (
		statuses = make([]usermd.StatusChangeMetadata, 0, 16)
		decoder  = json.NewDecoder(bytes.NewReader(b))
	)
	for {
		var sc gitbe.RecordStatusChangeV2
		err := decoder.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		status := convertRecordStatus(sc.NewStatus)
		scm := usermd.StatusChangeMetadata{
			Token:     token,
			Version:   version,
			Status:    uint32(status),
			Reason:    sc.StatusChangeMessage,
			PublicKey: sc.AdminPubKey,
			Signature: sc.Signature, // Only present on v2
			Timestamp: sc.Timestamp,
		}

		fmt.Printf("    Status: %v\n", backend.Statuses[status])
		fmt.Printf("    Reason: %v\n", scm.Reason)

		statuses = append(statuses, scm)
	}

	return statuses, nil
}

func convertRecordStatus(r gitbe.RecordStatusT) backend.StatusT {
	switch r {
	case gitbe.RecordStatusNotReviewed:
		return backend.StatusUnreviewed
	case gitbe.RecordStatusCensored:
		return backend.StatusCensored
	case gitbe.RecordStatusPublic:
		return backend.StatusPublic
	case gitbe.RecordStatusUnreviewedChanges:
		return backend.StatusUnreviewed
	case gitbe.RecordStatusArchived:
		return backend.StatusArchived
	}
	panic(fmt.Sprintf("invalid status %v", r))
}

func convertAuthDetails(proposalDir string) (*ticketvote.AuthDetails, error) {
	return &ticketvote.AuthDetails{
		Token:     "",
		Version:   0,
		Action:    "",
		PublicKey: "",
		Signature: "",
		Timestamp: 0,
		Receipt:   "",
	}, nil
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
	return &commentTypes{}, nil
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

func recordMetadataPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordMetadataFilename)
}

func payloadDirPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordPayloadPath)
}

func indexFilePath(proposalDir string) string {
	return filepath.Join(payloadDirPath(proposalDir), gitbe.IndexFilename)
}

func attachmentFilePath(proposalDir, attachmentFilename string) string {
	return filepath.Join(payloadDirPath(proposalDir), attachmentFilename)
}

func proposalGeneralPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamProposalGeneral)
}

func statusChangesPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStatusChanges)
}

// parseProposalName parses and returns the proposal name from the proposal
// index file.
func parseProposalName(proposalDir string) (string, error) {
	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", err
	}

	// Parse the proposal name from the index file. The
	// proposal name will always be the first line of the
	// file.
	r := bufio.NewReader(bytes.NewReader(b))
	name, _, err := r.ReadLine()
	if err != nil {
		return "", err
	}

	return string(name), nil
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

// newFile returns a new backend file.
func newFile(payload []byte, fileName string) backend.File {
	return backend.File{
		Name:    fileName,
		MIME:    http.DetectContentType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}
