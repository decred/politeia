// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"

	"github.com/decred/politeia/politeiad/api/v1"
)

var (
	// ErrRecordNotFound is emitted when a record could not be found
	ErrRecordNotFound = errors.New("record not found")

	// ErrFileNotFound is emitted when a file inside a record could not be
	// found
	ErrFileNotFound = errors.New("file not found")

	// ErrShutdown is emitted when the backend is shutting down.
	ErrShutdown = errors.New("backend is shutting down")

	// ErrShutdown is emitted when the backend is shutting down.
	ErrNoChanges = errors.New("no changes to record")

	// ErrInvalidTransition is emitted when an invalid status transition
	// occurs.  The only valid transitions are from unvetted -> vetted and
	// unvetted to censored.
	ErrInvalidTransition = errors.New("invalid record status transition")

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
	MDStatusIterationUnvetted MDStatusT = 4 // Changes are unvetted
)

var (
	// MDStatus converts a status code to a human readable error.
	MDStatus = map[MDStatusT]string{
		MDStatusInvalid:           "invalid",
		MDStatusUnvetted:          "unvetted",
		MDStatusVetted:            "vetted",
		MDStatusCensored:          "censored",
		MDStatusIterationUnvetted: "iteration unvetted",
	}
)

// RecordMetadata is the metadata of a record.
type RecordMetadata struct {
	Version   uint              // Iteration count of record
	Status    MDStatusT         // Current status of the record
	Merkle    [sha256.Size]byte // Merkle root of all files in record
	Timestamp int64             // Last updated
	Token     []byte            // Record authentication token
}

// MetadataStream describes a single metada stream.  The ID determines how and
// where it is stored.
type MetadataStream struct {
	ID      uint64 // Stream identity
	Payload string // String encoded metadata
}

// Record is a permanent that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata   // Internal metadata
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
		[]string) (*RecordMetadata, error)

	// Update vetted metadata (token, mdAppend, mdOverwrite)
	UpdateVettedMetadata([]byte, []MetadataStream,
		[]MetadataStream) error

	// Get unvetted record
	GetUnvetted([]byte) (*Record, error)

	// Get vetted record
	GetVetted([]byte) (*Record, error)

	// Set unvetted record status
	SetUnvettedStatus([]byte, MDStatusT, []MetadataStream,
		[]MetadataStream) (MDStatusT, error)

	// Inventory retrieves various record records.
	Inventory(uint, uint, bool) ([]Record, []Record, error)

	// Obtain plugin settings
	GetPlugins() ([]Plugin, error)

	// Pligin pass-through command
	Plugin(string, string) (string, string, error)

	// Close performs cleanup of the backend.
	Close()
}
