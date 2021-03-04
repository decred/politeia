// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"errors"
	"fmt"
	"regexp"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

var (
	// ErrRecordNotFound is emitted when a record could not be found
	ErrRecordNotFound = errors.New("record not found")

	// ErrRecordFound is emitted when a record is found while none was
	// expected.
	ErrRecordFound = errors.New("record found")

	// ErrFileNotFound is emitted when a file inside a record could not be
	// found
	ErrFileNotFound = errors.New("file not found")

	// ErrShutdown is emitted when the backend is shutting down.
	ErrShutdown = errors.New("backend is shutting down")

	// ErrNoChanges there are no changes to the record.
	ErrNoChanges = errors.New("no changes to record")

	// ErrChangesRecord is returned when a record would change when not
	// expected.
	ErrChangesRecord = errors.New("changes record")

	// ErrRecordLocked is returned when a record status is one that
	// does not allow any further changes.
	ErrRecordLocked = errors.New("record is locked")

	// ErrJournalsNotReplayed is returned when the journals have not
	// been replayed and the subsequent code expect it to be replayed.
	ErrJournalsNotReplayed = errors.New("journals have not been replayed")

	// ErrPluginInvalid is emitted when an invalid plugin ID is used.
	ErrPluginInvalid = errors.New("plugin invalid")

	// ErrPluginCmdInvalid is emitted when an invalid plugin command is
	// used.
	ErrPluginCmdInvalid = errors.New("plugin command invalid")

	// Plugin names must be all lowercase letters and have a length of <20
	PluginRE = regexp.MustCompile(`^[a-z]{1,20}$`)
)

// ContentVerificationError is returned when a submitted record contains
// unacceptable file formats or corrupt data.
type ContentVerificationError struct {
	ErrorCode    v1.ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (c ContentVerificationError) Error() string {
	return fmt.Sprintf("%v: %v", v1.ErrorStatus[c.ErrorCode], c.ErrorContext)
}

// File represents a record file.
type File struct {
	Name    string `json:"name"`    // Basename of the file
	MIME    string `json:"mime"`    // MIME type
	Digest  string `json:"digest"`  // SHA256 of decoded Payload
	Payload string `json:"payload"` // base64 encoded file
}

// MDStatusT represents the status of a backend record.
type MDStatusT int

const (
	// All possible MD status codes
	MDStatusInvalid           MDStatusT = 0 // Invalid status, this is a bug
	MDStatusUnvetted          MDStatusT = 1 // Unvetted record
	MDStatusVetted            MDStatusT = 2 // Vetted record
	MDStatusCensored          MDStatusT = 3 // Censored record
	MDStatusIterationUnvetted MDStatusT = 4 // Unvetted record that has been changed
	MDStatusArchived          MDStatusT = 5 // Vetted record that has been archived
)

var (
	// MDStatus converts a status code to a human readable error.
	MDStatus = map[MDStatusT]string{
		MDStatusInvalid:           "invalid",
		MDStatusUnvetted:          "unvetted",
		MDStatusVetted:            "vetted",
		MDStatusCensored:          "censored",
		MDStatusIterationUnvetted: "iteration unvetted",
		MDStatusArchived:          "archived",
	}
)

// StateTransitionError indicates an invalid record status transition.
type StateTransitionError struct {
	From MDStatusT
	To   MDStatusT
}

// Error satisfies the error interface.
func (s StateTransitionError) Error() string {
	return fmt.Sprintf("invalid record status transition %v (%v) -> %v (%v)",
		s.From, MDStatus[s.From], s.To, MDStatus[s.To])
}

// RecordMetadata is the metadata of a record.
const VersionRecordMD = 1

// RecordMetadata represents metadata that is created by the backend on record
// submission and updates.
type RecordMetadata struct {
	Version   uint64    `json:"version"`   // Version of the scruture
	Iteration uint64    `json:"iteration"` // Iteration count of record
	Status    MDStatusT `json:"status"`    // Current status of the record
	Merkle    string    `json:"merkle"`    // Merkle root of all files in record
	Timestamp int64     `json:"timestamp"` // Last updated
	Token     string    `json:"token"`     // Record authentication token, hex encoded
}

// MetadataStream describes a single metada stream.
type MetadataStream struct {
	ID      uint64 `json:"id"`      // Stream identity
	Payload string `json:"payload"` // String encoded metadata
}

// Record is a permanent Record that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata   // Internal metadata
	Version        string           // Version of Files
	Metadata       []MetadataStream // User provided metadata
	Files          []File           // User provided files
}

// PluginSettings are used to specify settings for a plugin at runtime.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings

	// Identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	Identity *identity.FullIdentity
}

// Backend provides an API for creating and editing records. When a record is
// first submitted it is considered to be an unvetted, i.e. non-public, record.
// Once the status of the record is updated to a public status, the record is
// considered to be vetted.
type Backend interface {
	// Create new record
	New([]MetadataStream, []File) (*RecordMetadata, error)

	// Update unvetted record
	UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []MetadataStream,
		filesAdd []File, filesDel []string) (*Record, error)

	// Update vetted record
	UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []MetadataStream,
		filesAdd []File, filesDel []string) (*Record, error)

	// Update unvetted metadata
	UpdateUnvettedMetadata(token []byte, mdAppend,
		mdOverwrite []MetadataStream) error

	// Update vetted metadata
	UpdateVettedMetadata(token []byte, mdAppend,
		mdOverwrite []MetadataStream) error

	// Set unvetted record status
	SetUnvettedStatus(token []byte, s MDStatusT, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// Set vetted record status
	SetVettedStatus(token []byte, s MDStatusT, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// Check if an unvetted record exists
	UnvettedExists(token []byte) bool

	// Check if a vetted record exists
	VettedExists(token []byte) bool

	// Get unvetted record
	GetUnvetted(token []byte, version string) (*Record, error)

	// Get vetted record
	GetVetted(token []byte, version string) (*Record, error)

	// Inventory retrieves various record records
	Inventory(uint, uint, uint, bool, bool) ([]Record, []Record, error)

	// Plugin pass-through command
	Plugin(string, string) (string, string, error) // command type, payload, error

	// Obtain plugin settings
	GetPlugins() ([]Plugin, error)

	// Close performs cleanup of the backend
	Close()
}
