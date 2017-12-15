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
	IdentityRoute  = "/v1/identity/"  // Retrieve identity
	NewRoute       = "/v1/new/"       // New record
	GetVettedRoute = "/v1/getvetted/" // Retrieve vetted record

	// Auth required
	GetUnvettedRoute       = "/v1/getunvetted/"       // Retrieve unvetted record
	InventoryRoute         = "/v1/inventory/"         // Inventory records
	SetUnvettedStatusRoute = "/v1/setunvettedstatus/" // Set unvetted status

	ChallengeSize = 32 // Size of challenge token in bytes
	IDSize        = 32 // Size of randomly generated ID in bytes

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

	// Record status codes (set and get)
	RecordStatusInvalid     RecordStatusT = 0 // Invalid status
	RecordStatusNotFound    RecordStatusT = 1 // Record not found
	RecordStatusNotReviewed RecordStatusT = 2 // Record has not been reviewed
	RecordStatusCensored    RecordStatusT = 3 // Record has been censored
	RecordStatusPublic      RecordStatusT = 4 // Record is publicly visible

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
		ErrorStatusEmpty:                         "no files provided",
	}

	// RecordStatus converts record status codes to human readable text.
	RecordStatus = map[RecordStatusT]string{
		RecordStatusInvalid:     "invalid status",
		RecordStatusNotFound:    "not found",
		RecordStatusNotReviewed: "not reviewed",
		RecordStatusCensored:    "censored",
		RecordStatusPublic:      "public",
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

// Record is an entire record and it's content.
type Record struct {
	Status    RecordStatusT `json:"status"`    // Current status
	Timestamp int64         `json:"timestamp"` // Last update

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`

	// User data
	Metadata string `json:"metadata"` // string encoded metadata
	Files    []File `json:"files"`    // Files that make up the record
}

// NewRecord creates a new record.  It must include all files that are part of
// the record and it may contain an optional metatda record.  Thet optional
// metadatarecord must be string encoded.
type NewRecord struct {
	Challenge string `json:"challenge"` // Random challenge
	Metadata  string `json:"metadata"`  // string encoded metadata
	Files     []File `json:"files"`     // Files that make up record
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
// it.
type SetUnvettedStatus struct {
	Challenge string        `json:"challenge"` // Random challenge
	Token     string        `json:"token"`     // Censorship token
	Status    RecordStatusT `json:"status"`    // Update unvetted status of record
}

// SetUnvettedStatus is a response to a SetUnvettedStatus.  The status field
// may be different than the status that was requested.  This should only
// happen when the command fails.
type SetUnvettedStatusReply struct {
	Response string        `json:"response"` // Challenge response
	Status   RecordStatusT `json:"status"`   // Actual status, may differ from request
}

//type UpdateUnvetted struct {
//	Challenge string `json:"challenge"` // Random challenge
//	Token     string `json:"token"`     // Censorship token
//	Files     []File `json:"files"`     // Files that make up the record
//}
//
//type UpdateUnvetted struct {
//	Challenge string `json:"challenge"` // Random challenge
//	Token     string `json:"token"`     // Censorship token
//}

// Inventory sends an (expensive and therefore authenticated) inventory request
// for vetted records (master branch) and branches (censored, unpublished etc)
// records.  This is a very expensive call and should be only issued at start
// of day.  The client should cache the reply.
// The IncludeFiles flag indicates if the records contain the record payload
// as well.  This can quickly become very large and should only be used when
// recovering the client side.
type Inventory struct {
	Challenge     string `json:"challenge"`     // Random challenge
	IncludeFiles  bool   `json:"includefiles"`  // Include files in records
	VettedCount   uint   `json:"vettedcount"`   // Last N vetted records
	BranchesCount uint   `json:"branchescount"` // Last N branches (censored, new etc)
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
