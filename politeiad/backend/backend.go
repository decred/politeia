// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1"
)

var (
	// ErrRecordNotFound is emitted when a record could not be found
	ErrRecordNotFound = errors.New("record not found")

	// ErrShutdown is emitted when the backend is shutting down.
	ErrShutdown = errors.New("backend is shutting down")

	// ErrInvalidTransition is emitted when an invalid status transition
	// occurs.  The only valid transitions are from unvetted -> vetted and
	// unvetted to censored.
	ErrInvalidTransition = errors.New("invalid record status transition")
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
	MDStatusInvalid  MDStatusT = 0
	MDStatusUnvetted MDStatusT = 1
	MDStatusVetted   MDStatusT = 2
	MDStatusCensored MDStatusT = 3
)

var (
	// MDStatus converts a status code to a human readable error.
	MDStatus = map[MDStatusT]string{
		MDStatusInvalid:  "invalid",
		MDStatusUnvetted: "unvetted",
		MDStatusVetted:   "vetted",
		MDStatusCensored: "censored",
	}
)

// RecordMetadata is the metadata of a record.
type RecordMetadata struct {
	Version            uint              // Iteration count of record
	Status             MDStatusT         // Current status of the record
	Merkle             [sha256.Size]byte // Merkle root of all files in record
	Timestamp          int64             // Last updated
	Token              []byte            // Record authentication token
	PaywallAddress     string            // Address the user needs to send to
	PaywallAmount      float64           // Amount the user needs to send
	PaywallTx          string            // Paywall transaction id
	PaywallTxNotBefore int64             // Transactions occurring before this time will not be valid.
}

// Record is a permanent that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata // Internal metadata
	Metadata       string         // User provided metadata
	Files          []File         // User provided files
}

type Backend interface {
	// Create new record
	New(string, []File) (*RecordMetadata, error)

	// Get unvetted record
	GetUnvetted([]byte) (*Record, error)

	// Get vetted record
	GetVetted([]byte) (*Record, error)

	// Set unvetted record status
	SetUnvettedStatus([]byte, MDStatusT) (MDStatusT, error)

	// Inventory retrieves various record records.
	Inventory(uint, uint, bool) ([]Record, []Record, error)

	// Close performs cleanup of the backend.
	Close()
}
