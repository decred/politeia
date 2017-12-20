// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
)

type ErrorStatusT int
type RecordStatusT int

const (
	// Routes
	IdentityRoute             = "/v1/identity/"       // Retrieve identity
	NewRecordRoute            = "/v1/newrecord/"      // New record
	UpdateUnvettedRoute       = "/v1/updateunvetted/" // Update unvetted record
	UpdateVettedMetadataRoute = "/v1/updatevettedmd/" // Update vetted metadata
	GetUnvettedRoute          = "/v1/getunvetted/"    // Retrieve unvetted record
	GetVettedRoute            = "/v1/getvetted/"      // Retrieve vetted record

	// Auth required
	InventoryRoute         = "/v1/inventory/"         // Inventory records
	SetUnvettedStatusRoute = "/v1/setunvettedstatus/" // Set unvetted status

	ChallengeSize      = 32         // Size of challenge token in bytes
	TokenSize          = 32         // Size of token
	MetadataStreamsMax = uint64(16) // Maximum number of metadata streams

	// Error status codes
	ErrorStatusInvalid                       ErrorStatusT = 0
	ErrorStatusInvalidRequestPayload         ErrorStatusT = 1
	ErrorStatusInvalidChallenge              ErrorStatusT = 2
	ErrorStatusInvalidFilename               ErrorStatusT = 3
	ErrorStatusInvalidFileDigest             ErrorStatusT = 4
	ErrorStatusInvalidBase64                 ErrorStatusT = 5
	ErrorStatusInvalidMIMEType               ErrorStatusT = 6
	ErrorStatusUnsupportedMIMEType           ErrorStatusT = 7
	ErrorStatusInvalidRecordStatusTransition ErrorStatusT = 8
	ErrorStatusEmpty                         ErrorStatusT = 9
	ErrorStatusInvalidMDID                   ErrorStatusT = 10
	ErrorStatusDuplicateMDID                 ErrorStatusT = 11
	ErrorStatusDuplicateFilename             ErrorStatusT = 12
	ErrorStatusFileNotFound                  ErrorStatusT = 13
	ErrorStatusNoChanges                     ErrorStatusT = 14

	// Record status codes (set and get)
	RecordStatusInvalid     RecordStatusT = 0 // Invalid status
	RecordStatusNotFound    RecordStatusT = 1 // Record not found
	RecordStatusNotReviewed RecordStatusT = 2 // Record has not been reviewed
	RecordStatusCensored    RecordStatusT = 3 // Record has been censored
	RecordStatusPublic      RecordStatusT = 4 // Record is publicly visible

	// Public visible record that has changes that are not public
	RecordStatusUnreviewedChanges RecordStatusT = 5

	// Default network bits
	DefaultMainnetHost = "politeia.decred.org"
	DefaultMainnetPort = "49374"
	DefaultTestnetHost = "politeia-testnet.decred.org"
	DefaultTestnetPort = "59374"

	Forward = "X-Forwarded-For"
)

var (
	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:                       "invalid status",
		ErrorStatusInvalidRequestPayload:         "invalid request payload",
		ErrorStatusInvalidChallenge:              "invalid challenge",
		ErrorStatusInvalidFilename:               "invalid filename",
		ErrorStatusInvalidFileDigest:             "invalid file digest",
		ErrorStatusInvalidBase64:                 "corrupt base64 string",
		ErrorStatusInvalidMIMEType:               "invalid MIME type detected",
		ErrorStatusUnsupportedMIMEType:           "unsupported MIME type",
		ErrorStatusInvalidRecordStatusTransition: "invalid record status transition",
		ErrorStatusEmpty:                         "empty record",
		ErrorStatusInvalidMDID:                   "invalid metadata id",
		ErrorStatusDuplicateMDID:                 "duplicate metadata id",
		ErrorStatusDuplicateFilename:             "duplicate filename",
		ErrorStatusFileNotFound:                  "file not found",
		ErrorStatusNoChanges:                     "no changes in record",
	}

	// RecordStatus converts record status codes to human readable text.
	RecordStatus = map[RecordStatusT]string{
		RecordStatusInvalid:           "invalid status",
		RecordStatusNotFound:          "not found",
		RecordStatusNotReviewed:       "not reviewed",
		RecordStatusCensored:          "censored",
		RecordStatusPublic:            "public",
		RecordStatusUnreviewedChanges: "unreviewed changes",
	}

	// Input validation
	RegexpSHA256 = regexp.MustCompile("[A-Fa-f0-9]{64}")

	// Verification errors
	ErrInvalidHex    = errors.New("corrupt hex string")
	ErrInvalidBase64 = errors.New("corrupt base64")
	ErrInvalidMerkle = errors.New("merkle roots do not match")
	ErrCorrupt       = errors.New("signature verification failed")
)

// Verify ensures that a CensorshipRecord properly describes the array of
// files.
func Verify(pid identity.PublicIdentity, csr CensorshipRecord, files []File) error {
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, file := range files {
		payload, err := base64.StdEncoding.DecodeString(file.Payload)
		if err != nil {
			return ErrInvalidBase64
		}

		// MIME
		mimeType := http.DetectContentType(payload)
		if !mime.MimeValid(mimeType) {
			return mime.ErrUnsupportedMimeType
		}

		// Digest
		h := sha256.New()
		h.Write(payload)
		d := h.Sum(nil)
		var digest [sha256.Size]byte
		copy(digest[:], d)

		digests = append(digests, &digest)
	}

	// Verify merkle root
	root := merkle.Root(digests)
	if hex.EncodeToString(root[:]) != csr.Merkle {
		return ErrInvalidMerkle
	}

	// Verify merkle+token signature
	token, err := hex.DecodeString(csr.Token)
	if err != nil {
		return ErrInvalidHex
	}

	merkleToken := make([]byte, len(root)+len(token))
	copy(merkleToken, root[:])
	copy(merkleToken[len(root[:]):], token)

	s, err := hex.DecodeString(csr.Signature)
	if err != nil {
		return ErrInvalidHex
	}
	var signature [identity.SignatureSize]byte
	copy(signature[:], s)
	if !pid.VerifyMessage(merkleToken, signature) {
		return ErrCorrupt
	}

	return nil
}

// CensorshipRecord contains the proof that a record was accepted for review.
// The proof is verifiable on the client side.
//
// The Merkle field contains the ordered merkle root of all files in the record.
// The Token field contains a random censorship token that is signed by the
// server private key.  The token can be used on the client to verify the
// authenticity of the CensorshipRecord.
type CensorshipRecord struct {
	Token     string `json:"token"`     // Censorship token
	Merkle    string `json:"merkle"`    // Merkle root of record
	Signature string `json:"signature"` // Signature of merkle+token
}

// Identity requests the record server identity.
type Identity struct {
	Challenge string `json:"challenge"` // Random challenge
}

// IdentityReply contains the server public identity.
type IdentityReply struct {
	Response  string `json:"response"`  // Signature of Challenge
	PublicKey string `json:"publickey"` // Public key
}

// File describes an individual file that is part of the record.  The
// directory structure must be flattened.  The server side SHALL verify MIME
// and Digest.
type File struct {
	Name    string `json:"name"`    // Suggested filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // Payload digest
	Payload string `json:"payload"` // File content
}

// MetadataStream identifies a metadata stream by its identity.
type MetadataStream struct {
	ID      uint64 `json:"id"`      // Stream identity
	Payload string `json:"payload"` // String encoded metadata
}

// Record is an entire record and it's content.
type Record struct {
	Status    RecordStatusT `json:"status"`    // Current status
	Timestamp int64         `json:"timestamp"` // Last update

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`

	// User data
	Metadata []MetadataStream `json:"metadata"` // Metadata streams
	Files    []File           `json:"files"`    // Files that make up the record
}

// NewRecord creates a new record.  It must include all files that are part of
// the record and it may contain an optional metatda record.  Thet optional
// metadatarecord must be string encoded.
type NewRecord struct {
	Challenge string           `json:"challenge"` // Random challenge
	Metadata  []MetadataStream `json:"metadata"`  // Metadata streams
	Files     []File           `json:"files"`     // Files that make up record
}

// NewRecordReply returns the CensorshipRecord that is associated with a valid
// record.  A valid record is not always going to be published.
type NewRecordReply struct {
	Response         string           `json:"response"` // Challenge response
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// GetUnvetted requests an unvetted record from the server.
type GetUnvetted struct {
	Challenge string `json:"challenge"` // Random challenge
	Token     string `json:"token"`     // Censorship token
}

// GetUnvettedReply returns an unvetted record.  It retrieves the censorship
// record and the actual files.
type GetUnvettedReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
}

// GetVetted requests a vetted record from the server.
type GetVetted struct {
	Challenge string `json:"challenge"` // Random challenge
	Token     string `json:"token"`     // Censorship token
}

// GetVettedReply returns a vetted record.  It retrieves the censorship
// record and the latest files in the record.
type GetVettedReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
}

// SetUnvettedStatus updates the status of an unvetted record.  This is used
// to either promote a record to the public viewable repository or to censor
// it. Additionally, metadata updates may travel along.
type SetUnvettedStatus struct {
	Challenge   string           `json:"challenge"`   // Random challenge
	Token       string           `json:"token"`       // Censorship token
	Status      RecordStatusT    `json:"status"`      // New status of record
	MDAppend    []MetadataStream `json:"mdappend"`    // Metadata streams to append
	MDOverwrite []MetadataStream `json:"mdoverwrite"` // Metadata streams to overwrite
}

// SetUnvettedStatus is a response to a SetUnvettedStatus.  The status field
// may be different than the status that was requested.  This should only
// happen when the command fails.
type SetUnvettedStatusReply struct {
	Response string        `json:"response"` // Challenge response
	Status   RecordStatusT `json:"status"`   // Actual status, may differ from request
}

// UpdateUnvetted update an unvetted record.
type UpdateUnvetted struct {
	Challenge   string           `json:"challenge"`   // Random challenge
	Token       string           `json:"token"`       // Censorship token
	MDAppend    []MetadataStream `json:"mdappend"`    // Metadata streams to append
	MDOverwrite []MetadataStream `json:"mdoverwrite"` // Metadata streams to overwrite
	FilesDel    []string         `json:"filesdel"`    // Files that will be deleted
	FilesAdd    []File           `json:"filesadd"`    // Files that are modified or added
}

// UpdateUnvetted returns a CensorshipRecord which may or may not have changed.
// Metadata updates do not create a new CensorshipRecord.
type UpdateUnvettedReply struct {
	Response string `json:"response"` // Challenge response

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// UpdateVettedMetadata update a vetted metadata.  This is allowed for
// priviledged users.  The record itself may not change.
type UpdateVettedMetadata struct {
	Challenge   string           `json:"challenge"`   // Random challenge
	Token       string           `json:"token"`       // Censorship token
	MDAppend    []MetadataStream `json:"mdappend"`    // Metadata streams to append
	MDOverwrite []MetadataStream `json:"mdoverwrite"` // Metadata streams to overwrite
}

// UpdateVettedMetadataReply returns a response challenge to an
// UpdateVettedMetadata command.
type UpdateVettedMetadataReply struct {
	Response string `json:"response"` // Challenge response
}

// Inventory sends an (expensive and therefore authenticated) inventory request
// for vetted records (master branch) and branches (censored, unpublished etc)
// records.  This is a very expensive call and should be only issued at start
// of day.  The client should cache the reply.
// The IncludeFiles flag indicates if the records contain the record payload
// as well.  This can quickly become very large and should only be used when
// recovering the client side.
type Inventory struct {
	Challenge string `json:"challenge"` // Random challenge
	// XXX add IncludeMD
	IncludeFiles bool `json:"includefiles"` // Include files in records
	// XXX add VettedStart and BranchesStart
	VettedCount   uint `json:"vettedcount"`   // Last N vetted records
	BranchesCount uint `json:"branchescount"` // Last N branches (censored, new etc)
}

// InventoryReply returns vetted and unvetted records.  If the Inventory
// command had IncludeFiles set to true the returned Records will also include
// the record files.  This obviously enlarges the payload size and should
// therefore be used only in disaster recovery scenarios.
type InventoryReply struct {
	Response string   `json:"response"` // Challenge response
	Vetted   []Record `json:"vetted"`   // Last N vetted records
	Branches []Record `json:"branches"` // Last N branches (censored, new etc)
}

// UserErrorReply returns details about an error that occurred while trying to
// execute a command due to bad input from the client.
type UserErrorReply struct {
	ErrorCode    ErrorStatusT `json:"errorcode"`              // Numeric error code
	ErrorContext []string     `json:"errorcontext,omitempty"` // Additional error information
}

// ServerErrorReply returns an error code that can be correlated with
// server logs.
type ServerErrorReply struct {
	ErrorCode int64 `json:"code"` // Server error code
}
