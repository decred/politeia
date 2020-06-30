// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/util"
	"github.com/subosito/gozaru"
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
	Name    string `json:"name"`    // Basename of the file
	MIME    string `json:"mime"`    // MIME type
	Digest  string `json:"digest"`  // SHA256 of decoded Payload
	Payload string `json:"payload"` // base64 encoded file
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
	Token     string    `json:"token"`     // Record authentication token, hex encoded
}

// MetadataStream describes a single metada stream.  The ID determines how and
// where it is stored.
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

// VerifyContent verifies that all provided MetadataStream and File are sane.
func VerifyContent(metadata []MetadataStream, files []File, filesDel []string) error {
	// Make sure all metadata is within maxima.
	for _, v := range metadata {
		if v.ID > v1.MetadataStreamsMax-1 {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidMDID,
				ErrorContext: []string{
					strconv.FormatUint(v.ID, 10),
				},
			}
		}
	}
	for i := range metadata {
		for j := range metadata {
			// Skip self and non duplicates.
			if i == j || metadata[i].ID != metadata[j].ID {
				continue
			}
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusDuplicateMDID,
				ErrorContext: []string{
					strconv.FormatUint(metadata[i].ID, 10),
				},
			}
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					v,
				},
			}
		}
	}

	// Now check files
	if len(files) == 0 {
		return ContentVerificationError{
			ErrorCode: v1.ErrorStatusEmpty,
		}
	}

	// Prevent bad filenames and duplicate filenames
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if files[i].Name == files[j].Name {
				return ContentVerificationError{
					ErrorCode: v1.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
		// Check against filesDel
		for _, v := range filesDel {
			if files[i].Name == v {
				return ContentVerificationError{
					ErrorCode: v1.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
	}

	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Validate digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Decode base64 payload
		var err error
		payload, err := base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidBase64,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Calculate payload digest
		dp := util.Digest(payload)
		if !bytes.Equal(d[:], dp) {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Verify MIME
		detectedMIMEType := mime.DetectMimeType(payload)
		if detectedMIMEType != files[i].MIME {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{
					files[i].Name,
					detectedMIMEType,
				},
			}
		}

		if !mime.MimeValid(files[i].MIME) {
			return ContentVerificationError{
				ErrorCode: v1.ErrorStatusUnsupportedMIMEType,
				ErrorContext: []string{
					files[i].Name,
					files[i].MIME,
				},
			}
		}
	}

	return nil
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
