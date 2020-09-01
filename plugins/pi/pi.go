// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a plugin for functionality that is specific to decred's
// proposal system.
package pi

import (
	"encoding/json"
	"fmt"
)

type ErrorStatusT int

const (
	Version uint32 = 1
	ID             = "pi"

	// Plugin commands
	CmdProposalDetails = "proposaldetails"
	CmdProposals       = "proposals"

	// Metadata stream IDs. All metadata streams in this plugin will
	// use 1xx numbering.
	MDStreamIDProposalGeneral = 101
	MDStreamIDStatusChange    = 102

	// FilenameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it needs to
	// be included in the merkle root that politeiad signs.
	FilenameProposalMetadata = "proposalmetadata.json"

	// User error status codes
	ErrorStatusInvalid       ErrorStatusT = 0
	ErrorStatusLinkToInvalid ErrorStatusT = 1
)

var (
	// ErrorStatus contains human readable user error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:       "error status invalid",
		ErrorStatusLinkToInvalid: "linkto invalid",
	}
)

// UserError represents an error that is caused by the user.
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("pi plugin error code: %v", e.ErrorCode)
}

// ProposalMetadata contains proposal metadata that is provided by the user on
// proposal submission. ProposalMetadata is saved to politeiad as a file, not
// as a metadata stream, since it needs to be included in the merkle root that
// politeiad signs.
type ProposalMetadata struct {
	// Name is the name of the proposal.
	Name string `json:"name"`

	// LinkTo specifies a public proposal token to link this proposal
	// to. Ex, an RFP sumbssion must link to the RFP proposal.
	LinkTo string `json:"linkto,omitempty"`

	// LinkBy is a UNIX timestamp that serves as a deadline for other
	// proposals to link to this proposal. Ex, an RFP submission cannot
	// link to an RFP proposal once the RFP's LinkBy deadline is past.
	LinkBy int64 `json:"linkby,omitempty"`
}

// EncodeProposalMetadata encodes a ProposalMetadata into a JSON byte slice.
func EncodeProposalMetadata(pm ProposalMetadata) ([]byte, error) {
	return json.Marshal(pm)
}

// DecodeProposalMetadata decodes a ProposalMetadata into a JSON byte slice.
func DecodeProposalMetadata(payload []byte) (*ProposalMetadata, error) {
	var pm ProposalMetadata
	err := json.Unmarshal(payload, &pm)
	if err != nil {
		return nil, err
	}
	return &pm, nil
}

// ProposalGeneral represents general proposal metadata that is saved on
// proposal submission. ProposalGeneral is saved to politeiad as a metadata
// stream.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalGeneral struct {
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
	Timestamp int64  `json:"timestamp"` // Submission UNIX timestamp
}

// EncodeProposalGeneral encodes a ProposalGeneral into a JSON byte slice.
func EncodeProposalGeneral(pg ProposalGeneral) ([]byte, error) {
	return json.Marshal(pg)
}

// DecodeProposalGeneral decodes a ProposalGeneral into a JSON byte slice.
func DecodeProposalGeneral(payload []byte) (*ProposalGeneral, error) {
	var pg ProposalGeneral
	err := json.Unmarshal(payload, &pg)
	if err != nil {
		return nil, err
	}
	return &pg, nil
}

// StatusChange represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	// Status    PropStatusT `json:"status"`
	Version   string `json:"version"`
	Message   string `json:"message,omitempty"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}
