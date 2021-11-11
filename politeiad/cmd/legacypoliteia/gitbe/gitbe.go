// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package gitbe contains the git backend types and filenames that are required
// by the legacypoliteia tool.
package gitbe

const (
	// Proposal sub-directory paths. These paths are relative to the proposal
	// root directory.
	RecordPayloadPath = "payload/"
	DecredPluginPath  = "plugins/decred/"

	// Record metadata filename. The record metadata file is located in the
	// proposal root directory.
	RecordMetadataFilename = "recordmetadata.json"

	// Proposal file filenames. The proposal files are located in the payload
	// directory.
	IndexFilename            = "index.md"
	ProposalMetadataFilename = "proposalmetadata.json"

	// PublicKey is the git backend politeia public key. The public key changed
	// when politeia migrated to tstore.
	PublicKey = "a70134196c3cdf3f85f8af6abaa38c15feb7bccf5e6d3db6212358363465e502"
)

// RecordMetadata is the metadata of a record.
type RecordMetadata struct {
	Version   uint64    `json:"version"`   // Version of the scruture
	Iteration uint64    `json:"iteration"` // Iteration count of record
	Status    MDStatusT `json:"status"`    // Current status of the record
	Merkle    string    `json:"merkle"`    // Merkle root of all files in record
	Timestamp int64     `json:"timestamp"` // Last updated
	Token     string    `json:"token"`     // Record authentication token
}

// MDStatusT represents a record metadata status.
type MDStatusT int

const (
	MDStatusInvalid           MDStatusT = 0
	MDStatusUnvetted          MDStatusT = 1
	MDStatusVetted            MDStatusT = 2
	MDStatusCensored          MDStatusT = 3
	MDStatusIterationUnvetted MDStatusT = 4
	MDStatusArchived          MDStatusT = 5
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission. It is attached to a proposal submission as a politeiawww
// Metadata object and is saved to politeiad as a File, not as a
// MetadataStream. The filename is defined by FilenameProposalMetadata.
//
// The reason it is saved to politeiad as a File is because politeiad only
// includes Files in the merkle root calculation. This is user defined metadata
// so it must be included in the proposal signature on submission. If it were
// saved to politeiad as a MetadataStream then it would not be included in the
// merkle root, thus causing an error where the client calculated merkle root
// if different than the politeiad calculated merkle root.
type ProposalMetadata struct {
	Name   string `json:"name"`             // Proposal name
	LinkTo string `json:"linkto,omitempty"` // Token of proposal to link to
	LinkBy int64  `json:"linkby,omitempty"` // UNIX timestamp of RFP deadline
}
