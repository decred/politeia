// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"

	"github.com/decred/dcrtime/merkle"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/thi4go/politeia/politeiad/api/v1/mime"
)

type ErrorStatusT int
type RecordStatusT int

const (
	// Routes
	IdentityRoute             = "/v1/identity/"       // Retrieve identity
	NewRecordRoute            = "/v1/newrecord/"      // New record
	UpdateUnvettedRoute       = "/v1/updateunvetted/" // Update unvetted record
	UpdateVettedRoute         = "/v1/updatevetted/"   // Update vetted record
	UpdateVettedMetadataRoute = "/v1/updatevettedmd/" // Update vetted metadata
	GetUnvettedRoute          = "/v1/getunvetted/"    // Retrieve unvetted record
	GetVettedRoute            = "/v1/getvetted/"      // Retrieve vetted record

	// Auth required
	InventoryRoute         = "/v1/inventory/"                  // Inventory records
	SetUnvettedStatusRoute = "/v1/setunvettedstatus/"          // Set unvetted status
	SetVettedStatusRoute   = "/v1/setvettedstatus/"            // Set vetted status
	PluginCommandRoute     = "/v1/plugin/"                     // Send a command to a plugin
	PluginInventoryRoute   = PluginCommandRoute + "inventory/" // Inventory all plugins
	UpdateReadmeRoute      = "/v1/updatereadme/"               // Update README

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
	ErrorStatusRecordFound                   ErrorStatusT = 15
	ErrorStatusInvalidRPCCredentials         ErrorStatusT = 16

	// Record status codes (set and get)
	RecordStatusInvalid           RecordStatusT = 0 // Invalid status
	RecordStatusNotFound          RecordStatusT = 1 // Record not found
	RecordStatusNotReviewed       RecordStatusT = 2 // Record has not been reviewed
	RecordStatusCensored          RecordStatusT = 3 // Record has been censored
	RecordStatusPublic            RecordStatusT = 4 // Record is publicly visible
	RecordStatusUnreviewedChanges RecordStatusT = 5 // Unvetted record that has been changed
	RecordStatusArchived          RecordStatusT = 6 // Vetted record that has been archived

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
		ErrorStatusRecordFound:                   "record found",
		ErrorStatusInvalidRPCCredentials:         "invalid RPC client credentials",
	}

	// RecordStatus converts record status codes to human readable text.
	RecordStatus = map[RecordStatusT]string{
		RecordStatusInvalid:           "invalid status",
		RecordStatusNotFound:          "not found",
		RecordStatusNotReviewed:       "not reviewed",
		RecordStatusCensored:          "censored",
		RecordStatusPublic:            "public",
		RecordStatusUnreviewedChanges: "unreviewed changes",
		RecordStatusArchived:          "archived",
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
		mimeType := mime.DetectMimeType(payload)
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

	s, err := hex.DecodeString(csr.Signature)
	if err != nil {
		return ErrInvalidHex
	}
	var signature [identity.SignatureSize]byte
	copy(signature[:], s)
	r := hex.EncodeToString(root[:])
	if !pid.VerifyMessage([]byte(r+csr.Token), signature) {
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
	Version  string           `json:"version"`  // Version of this record
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
	Version   string `json:"version"`   // Record version
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

// SetUnvettedStatus is a response to a SetUnvettedStatus.  It returns the
// potentially modified record without the Files.
type SetUnvettedStatusReply struct {
	Response string `json:"response"` // Challenge response
}

// SetVettedStatus updates the status of a vetted record. This is used to
// archive a vetted proposal. Additionally, metadata updates may travel along.
type SetVettedStatus struct {
	Challenge   string           `json:"challenge"`   // Random challenge
	Token       string           `json:"token"`       // Censorship token
	Status      RecordStatusT    `json:"status"`      // New status of record
	MDAppend    []MetadataStream `json:"mdappend"`    // Metadata streams to append
	MDOverwrite []MetadataStream `json:"mdoverwrite"` // Metadata streams to overwrite
}

// SetVettedStatusReply is a response to SetVettedStatus. It returns the
// potentially modified record without the Files.
type SetVettedStatusReply struct {
	Response string `json:"response"` // Challenge response
}

// UpdateRecord update an unvetted record.
type UpdateRecord struct {
	Challenge   string           `json:"challenge"`   // Random challenge
	Token       string           `json:"token"`       // Censorship token
	MDAppend    []MetadataStream `json:"mdappend"`    // Metadata streams to append
	MDOverwrite []MetadataStream `json:"mdoverwrite"` // Metadata streams to overwrite
	FilesDel    []string         `json:"filesdel"`    // Files that will be deleted
	FilesAdd    []File           `json:"filesadd"`    // Files that are modified or added
}

// UpdateRecordReply returns a CensorshipRecord which may or may not have
// changed.  Metadata only updates do not create a new CensorshipRecord.
type UpdateRecordReply struct {
	Response string `json:"response"` // Challenge response
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

// UpdateReadme updated the README.md file in the vetted and unvetted repos.
type UpdateReadme struct {
	Challenge string `json:"challenge"` // Random challenge
	Content   string `json:"content"`   // New content of README.md
}

// UpdateReadmeReply returns a response challenge to an
// UpdateReadme command.
type UpdateReadmeReply struct {
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
	AllVersions   bool `json:"allversions"`   // Return all versions of the proposals
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

// PluginSetting is a structure that holds key/value pairs of a plugin setting.
type PluginSetting struct {
	Key   string `json:"key"`   // Name of setting
	Value string `json:"value"` // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          `json:"id"`       // Identifier
	Version  string          `json:"version"`  // Version
	Settings []PluginSetting `json:"settings"` // Settings
}

// PluginInventory retrieves all active plugins and their settings.
type PluginInventory struct {
	Challenge string `json:"challenge"` // Random challenge
}

// PluginInventoryReply returns all plugins and their settings.
type PluginInventoryReply struct {
	Response string   `json:"response"` // Challenge response
	Plugins  []Plugin `json:"plugins"`  // Plugins and their settings
}

// PluginCommand sends a command to a plugin.
type PluginCommand struct {
	Challenge string `json:"challenge"` // Random challenge
	ID        string `json:"id"`        // Plugin identifier
	Command   string `json:"command"`   // Command identifier
	CommandID string `json:"commandid"` // User setable command identifier
	Payload   string `json:"payload"`   // Actual command
}

// PluginCommandReply is the reply to a PluginCommand.
type PluginCommandReply struct {
	Response  string `json:"response"`  // Challenge response
	ID        string `json:"id"`        // Plugin identifier
	Command   string `json:"command"`   // Command identifier
	CommandID string `json:"commandid"` // User setable command identifier
	Payload   string `json:"payload"`   // Actual command reply
}
