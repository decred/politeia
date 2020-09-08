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

type PropStatusT int
type ErrorStatusT int

const (
	Version uint32 = 1
	ID             = "pi"

	// Plugin commands
	CmdProposals = "proposals" // Get proposals plugin data

	// Metadata stream IDs. All metadata streams in this plugin will
	// use 1xx numbering.
	MDStreamIDProposalGeneral = 101
	MDStreamIDStatusChange    = 102

	// FilenameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FilenameProposalMetadata = "proposalmetadata.json"

	// Proposal status codes
	PropStatusInvalid   PropStatusT = 0 // Invalid status
	PropStatusUnvetted  PropStatusT = 1 // Prop has not been vetted
	PropStatusPublic    PropStatusT = 2 // Prop has been made public
	PropStatusCensored  PropStatusT = 3 // Prop has been censored
	PropStatusAbandoned PropStatusT = 4 // Prop has been abandoned

	// User error status codes
	ErrorStatusInvalid         ErrorStatusT = 0
	ErrorStatusLinkToInvalid   ErrorStatusT = 1
	ErrorStatusWrongPropStatus ErrorStatusT = 2
	ErrorStatusWrongVoteStatus ErrorStatusT = 3
)

var (
	// StatusChanges contains the allowed proposal status change
	// transitions. If StatusChanges[currentStatus][newStatus] exists
	// then the status change is allowed.
	StatusChanges = map[PropStatusT]map[PropStatusT]struct{}{
		PropStatusUnvetted:  map[PropStatusT]struct{}{},
		PropStatusPublic:    map[PropStatusT]struct{}{},
		PropStatusCensored:  map[PropStatusT]struct{}{},
		PropStatusAbandoned: map[PropStatusT]struct{}{},
	}

	// ErrorStatus contains human readable user error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:         "error status invalid",
		ErrorStatusLinkToInvalid:   "linkto invalid",
		ErrorStatusWrongPropStatus: "wrong proposal status",
		ErrorStatusWrongVoteStatus: "wrong vote status",
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

// Proposals requests the plugin data for the provided proposals. This includes
// pi plugin data as well as other plugin data such as comments plugin data.
// This command aggregates all proposal plugin data into a single call.
type Proposals struct {
	Tokens []string `json:"tokens"`
}

// EncodeProposals encodes a Proposals into a JSON byte slice.
func EncodeProposals(p Proposals) ([]byte, error) {
	return json.Marshal(p)
}

// DecodeProposals decodes a Proposals into a JSON byte slice.
func DecodeProposals(payload []byte) (*Proposals, error) {
	var p Proposals
	err := json.Unmarshal(payload, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ProposalPluginData represents the plugin data of a proposal.
type ProposalPluginData struct {
	Comments   uint64   `json:"comments"`   // Number of comments
	LinkedFrom []string `json:"linkedfrom"` // Linked from list
}

// ProposalsReply is the reply to the Proposals command. The proposals map will
// not contain an entry for tokens that do not correspond to actual proposals.
type ProposalsReply struct {
	Proposals map[string]ProposalPluginData `json:"proposals"`
}

// EncodeProposalsReply encodes a ProposalsReply into a JSON byte slice.
func EncodeProposalsReply(pr ProposalsReply) ([]byte, error) {
	return json.Marshal(pr)
}

// DecodeProposalsReply decodes a ProposalsReply into a JSON byte slice.
func DecodeProposalsReply(payload []byte) (*ProposalsReply, error) {
	var pr ProposalsReply
	err := json.Unmarshal(payload, &pr)
	if err != nil {
		return nil, err
	}
	return &pr, nil
}
