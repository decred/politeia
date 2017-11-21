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
	// ErrProposalNotFound is emitted when a proposal could not be found
	ErrProposalNotFound = errors.New("proposal not found")

	// ErrShutdown is emitted when the backend is shutting down.
	ErrShutdown = errors.New("backend is shutting down")

	// ErrInvalidTransition is emitted when an invalid status transition
	// occurs.  The only valid transitions are from unvetted -> vetted and
	// unvetted to censored.
	ErrInvalidTransition = errors.New("invalid proposal status transition")
)

// ContentVerificationError is returned when a submitted proposal contains
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

type PSRStatusT int

const (
	// All possible PSR status codes
	PSRStatusInvalid  PSRStatusT = 0
	PSRStatusUnvetted PSRStatusT = 1
	PSRStatusVetted   PSRStatusT = 2
	PSRStatusCensored PSRStatusT = 3
)

var (
	// PSRStatus converts a status code to a human readable error.
	PSRStatus = map[PSRStatusT]string{
		PSRStatusInvalid:  "invalid",
		PSRStatusUnvetted: "unvetted",
		PSRStatusVetted:   "vetted",
		PSRStatusCensored: "censored",
	}
)

// ProposalStorageRecord is the metadata of a proposal.
type ProposalStorageRecord struct {
	Version   uint              // Iteration count of proposal
	Status    PSRStatusT        // Current status of the proposal
	Merkle    [sha256.Size]byte // Merkle root of all files in proposal
	Timestamp int64             // Last updated
	Token     []byte            // Proposal authentication token
}

// ProposalRecord is a ProposalStorageRecord that includes the files.
type ProposalRecord struct {
	ProposalStorageRecord ProposalStorageRecord
	Files                 []File
}

type Backend interface {
	// Create new proposal
	New([]File) (*ProposalStorageRecord, error)

	// Get unvetted proposal
	GetUnvetted([]byte) (*ProposalRecord, error)

	// Get vetted proposal
	GetVetted([]byte) (*ProposalRecord, error)

	// Set unvetted proposal status
	SetUnvettedStatus([]byte, PSRStatusT) (PSRStatusT, error)

	// Inventory retrieves various proposal records.
	Inventory(uint, uint, bool) ([]ProposalRecord, []ProposalRecord, error)

	// Close performs cleanup of the backend.
	Close()
}
