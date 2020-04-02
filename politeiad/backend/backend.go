// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/thi4go/politeia/politeiad/api/v1"
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

	// ErrRecordArchived is returned when an update was attempted on a
	// archived record.
	ErrRecordArchived = errors.New("record is archived")

	// ErrJournalsNotReplayed is returned when the journals have not been replayed
	// and the subsequent code expect it to be replayed
	ErrJournalsNotReplayed = errors.New("journals have not been replayed")

	// Plugin names must be all lowercase letters and have a length of <20
	PluginRE = regexp.MustCompile(`^[a-z]{1,20}$`)
)

// ContentVerificationError is returned when a submitted record contains
// unacceptable file formats or corrupt data.
type ContentVerificationError struct {
	ErrorCode    v1.ErrorStatusT
	ErrorContext []string
}

func (c ContentVerificationError) Error() string {
	return fmt.Sprintf("%v: %v", v1.ErrorStatus[c.ErrorCode], c.ErrorContext)
}

type File struct {
	Name    string // Basename of the file
	MIME    string // MIME type
	Digest  string // SHA256 of decoded Payload
	Payload string // base64 encoded file
}

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

func (s StateTransitionError) Error() string {
	return fmt.Sprintf("invalid record status transition %v (%v) -> %v (%v)",
		s.From, MDStatus[s.From], s.To, MDStatus[s.To])
}

// RecordMetadata is the metadata of a record.
const VersionRecordMD = 1

type RecordMetadata struct {
	Version   uint64    `json:"version"`   // Version of the scruture
	Iteration uint64    `json:"iteration"` // Iteration count of record
	Status    MDStatusT `json:"status"`    // Current status of the record
	Merkle    string    `json:"merkle"`    // Merkle root of all files in record
	Timestamp int64     `json:"timestamp"` // Last updated
	Token     string    `json:"token"`     // Record authentication token
}

// MetadataStream describes a single metada stream.  The ID determines how and
// where it is stored.
type MetadataStream struct {
	ID      uint64 // Stream identity
	Payload string // String encoded metadata
}

// Record is a permanent Record that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata   // Internal metadata
	Version        string           // Version of Files
	Metadata       []MetadataStream // User provided metadata
	Files          []File           // User provided files
}

// PluginSettings
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings
}

type Backend interface {
	// Create new record
	New([]MetadataStream, []File) (*RecordMetadata, error)

	// Update unvetted record (token, mdAppend, mdOverwrite, fAdd, fDelete)
	UpdateUnvettedRecord([]byte, []MetadataStream, []MetadataStream, []File,
		[]string) (*Record, error)

	// Update vetted record (token, mdAppend, mdOverwrite, fAdd, fDelete)
	UpdateVettedRecord([]byte, []MetadataStream, []MetadataStream, []File,
		[]string) (*Record, error)

	// Update vetted metadata (token, mdAppend, mdOverwrite)
	UpdateVettedMetadata([]byte, []MetadataStream,
		[]MetadataStream) error

	// Update README.md file at the root of git repo
	UpdateReadme(string) error

	// Check if an unvetted record exists
	UnvettedExists([]byte) bool

	// Check if a vetted record exists
	VettedExists([]byte) bool

	// Get unvetted record
	GetUnvetted([]byte) (*Record, error)

	// Get vetted record
	GetVetted([]byte, string) (*Record, error)

	// Set unvetted record status
	SetUnvettedStatus([]byte, MDStatusT, []MetadataStream,
		[]MetadataStream) (*Record, error)

	// Set vetted record status
	SetVettedStatus([]byte, MDStatusT, []MetadataStream,
		[]MetadataStream) (*Record, error)

	// Inventory retrieves various record records.
	Inventory(uint, uint, bool, bool) ([]Record, []Record, error)

	// Obtain plugin settings
	GetPlugins() ([]Plugin, error)

	// Plugin pass-through command
	Plugin(string, string) (string, string, error) // command type, payload, error

	// Close performs cleanup of the backend.
	Close()
}
