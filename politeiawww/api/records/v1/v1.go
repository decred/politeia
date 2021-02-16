// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/records/v1"

	// Record routes
	RouteNew        = "/new"
	RouteEdit       = "/edit"
	RouteSetStatus  = "/setstatus"
	RouteDetails    = "/details"
	RouteRecords    = "/records"
	RouteInventory  = "/inventory"
	RouteTimestamps = "/timestamps"

	// Metadata routes
	RouteUserRecords = "/userrecords"

	// Record states
	RecordStateUnvetted = "unvetted"
	RecordStateVetted   = "vetted"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT int

const (
	// Error codes
	ErrorCodeInvalid                      ErrorCodeT = 0
	ErrorCodeInputInvalid                 ErrorCodeT = 1
	ErrorCodeFileNameInvalid              ErrorCodeT = 2
	ErrorCodeFileMIMEInvalid              ErrorCodeT = 3
	ErrorCodeFileDigestInvalid            ErrorCodeT = 4
	ErrorCodeFilePayloadInvalid           ErrorCodeT = 5
	ErrorCodeMetadataStreamIDInvalid      ErrorCodeT = 6
	ErrorCodeMetadataStreamPayloadInvalid ErrorCodeT = 8
	ErrorCodePublicKeyInvalid             ErrorCodeT = 9
	ErrorCodeSignatureInvalid             ErrorCodeT = 10
	ErrorCodeRecordTokenInvalid           ErrorCodeT = 11
	ErrorCodeRecordStateInvalid           ErrorCodeT = 12
	ErrorCodeRecordNotFound               ErrorCodeT = 13
	ErrorCodeRecordLocked                 ErrorCodeT = 14
	ErrorCodeNoRecordChanges              ErrorCodeT = 15
	ErrorCodeRecordStatusInvalid          ErrorCodeT = 16
	ErrorCodeStatusReasonNotFound         ErrorCodeT = 17
	ErrorCodePageSizeExceeded             ErrorCodeT = 18
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                      "error invalid",
		ErrorCodeInputInvalid:                 "input invalid",
		ErrorCodeFileNameInvalid:              "file name invalid",
		ErrorCodeFileMIMEInvalid:              "file mime invalid",
		ErrorCodeFileDigestInvalid:            "file digest invalid",
		ErrorCodeFilePayloadInvalid:           "file payload invalid",
		ErrorCodeMetadataStreamIDInvalid:      "mdstream id invalid",
		ErrorCodeMetadataStreamPayloadInvalid: "mdstream payload invalid",
		ErrorCodePublicKeyInvalid:             "public key invalid",
		ErrorCodeSignatureInvalid:             "signature invalid",
		ErrorCodeRecordTokenInvalid:           "record token invalid",
		ErrorCodeRecordStateInvalid:           "record state invalid",
		ErrorCodeRecordNotFound:               "record not found",
		ErrorCodeRecordLocked:                 "record locked",
		ErrorCodeNoRecordChanges:              "no record changes",
		ErrorCodeRecordStatusInvalid:          "record status invalid",
		ErrorCodeStatusReasonNotFound:         "status reason not found",
		ErrorCodePageSizeExceeded:             "page size exceeded",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    int    `json:"errorcode"`
	ErrorContext string `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e PluginErrorReply) Error() string {
	return fmt.Sprintf("plugin %v error code: %v", e.PluginID, e.ErrorCode)
}

// ServerErrorReply is the reply that the server returns when it encounters an
// unrecoverable error while executing a command. The HTTP status code will be
// 500 and the ErrorCode field will contain a UNIX timestamp that the user can
// provide to the server admin to track down the error details in the logs.
type ServerErrorReply struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e ServerErrorReply) Error() string {
	return fmt.Sprintf("server error: %v", e.ErrorCode)
}

// RecordStatusT represents a record status.
type RecordStatusT int

const (
	// RecordStatusInvalid is an invalid record status.
	RecordStatusInvalid RecordStatusT = 0

	// RecordStatusUnreviewed indicates that a record has been
	// submitted but has not been made public yet. A record with
	// this status will have a state of unvetted.
	RecordStatusUnreviewed RecordStatusT = 1

	// RecordStatusPublic indicates that a record has been made public.
	// A record with this status will have a state of vetted.
	RecordStatusPublic RecordStatusT = 2

	// RecordStatusCensored indicates that a record has been censored.
	// The record state can be either unvetted or vetted depending on
	// whether the record was censored before or after it was made
	// public. All user submitted content of a censored record will
	// have been permanently deleted.
	RecordStatusCensored RecordStatusT = 3

	// RecordStatusUnreviewedChanges has been deprecated.
	RecordStatusUnreviewedChanges RecordStatusT = 4

	// RecordStatusArchived represents a record that has been archived.
	// Both unvetted and vetted records can be marked as archived.
	// Unlike with censored records, the user submitted content of an
	// archived record is not deleted.
	RecordStatusArchived RecordStatusT = 5
)

var (
	// RecordStatuses contains the human readable record statuses.
	RecordStatuses = map[RecordStatusT]string{
		RecordStatusInvalid:    "invalid",
		RecordStatusUnreviewed: "unreviewed",
		RecordStatusPublic:     "public",
		RecordStatusCensored:   "censored",
		RecordStatusArchived:   "archived",
	}
)

// File describes an individual file that is part of the record.
type File struct {
	Name    string `json:"name"`    // Filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // File content, base64 encoded
}

// MetadataStream describes a record metadata stream.
type MetadataStream struct {
	PluginID string `json:"pluginid,omitempty"` // Plugin ID
	ID       uint64 `json:"id"`                 // Metadata stream ID
	Payload  string `json:"payload"`            // JSON encoded
}

// CensorshipRecord contains cryptographic proof that a record was accepted for
// review by the server. The proof is verifiable by the client.
type CensorshipRecord struct {
	// Token is a random censorship token that is generated by the
	// server. It serves as a unique identifier for the record.
	Token string `json:"token"`

	// Merkle is the ordered merkle root of all files and metadata in
	// in the record.
	Merkle string `json:"merkle"`

	// Signature is the server signature of the Merkle+Token.
	Signature string `json:"signature"`
}

// Record represents a record and all of its content.
type Record struct {
	State     string           `json:"state"`     // Record state
	Status    RecordStatusT    `json:"status"`    // Record status
	Version   string           `json:"version"`   // Version of this record
	Timestamp int64            `json:"timestamp"` // Last update
	Username  string           `json:"username"`  // Author username
	Metadata  []MetadataStream `json:"metadata"`  // Metadata streams
	Files     []File           `json:"files"`     // User submitted files

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// UserMetadata contains user metadata about a politeiad record. It is
// generated by the server and saved to politeiad as a metadata stream.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all user submitted politeiad files.
type UserMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// StatusChange represents a record status change. It is generated by the
// server and saved to politeiad as a metadata stream.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	Token     string        `json:"token"`
	Version   string        `json:"version"`
	Status    RecordStatusT `json:"status"`
	Reason    string        `json:"message,omitempty"`
	PublicKey string        `json:"publickey"`
	Signature string        `json:"signature"`
	Timestamp int64         `json:"timestamp"`
}

// New submits a new record.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all record Files.
type New struct {
	Files     []File `json:"files"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

// NewReply is the reply to the New command.
type NewReply struct {
	Record Record `json:"record"`
}

// Edit edits an existing record.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all record Files.
type Edit struct {
	State     string `json:"state"`
	Token     string `json:"token"`
	Files     []File `json:"files"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

// EditReply is the reply to the Edit command.
type EditReply struct {
	Record Record `json:"record"`
}

// SetStatus sets the status of a record. Some status changes require a reason
// to be included.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type SetStatus struct {
	State     string        `json:"state"`
	Token     string        `json:"token"`
	Version   string        `json:"version"`
	Status    RecordStatusT `json:"status"`
	Reason    string        `json:"reason,omitempty"`
	PublicKey string        `json:"publickey"`
	Signature string        `json:"signature"`
}

// SetStatusReply is the reply to the SetStatus command.
type SetStatusReply struct {
	Record Record `json:"record"`
}

// Details requests the details of a record. The full record will be returned.
type Details struct {
	Token   string `json:"token"`
	State   string `json:"state"`
	Version string `json:"version"`
}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	Record Record `json:"record"`
}

const (
	// RecordsPageSize is the maximum number of records that can be
	// requested in a Records request.
	RecordsPageSize = 10
)

// Records requests a batch of records.
//
// Only the record metadata is returned. The Details command must be used to
// retrieve the record files or a specific version of the record. Since record
// files are not included in the reply, unvetted records are returned to all
// users.
type Records struct {
	State  string   `json:"state"`
	Tokens []string `json:"tokens"`
}

// RecordsReply is the reply to the Records command. Any tokens that did not
// correspond to a record will not be included in the reply.
type RecordsReply struct {
	Records map[string]Record `json:"records"` // [token]Record
}

const (
	// InventoryPageSize is the maximum number of tokens that will be
	// returned for any single status in an inventory reply.
	InventoryPageSize uint32 = 20
)

// Inventory requests the tokens of the records in the inventory, categorized
// by record state and record status. The tokens are ordered by the timestamp
// of their most recent status change, sorted from newest to oldest.
//
// The state, status, and page arguments can be provided to request a specific
// page of record tokens.
//
// If no status is provided then a page of tokens for all statuses are
// returned. The state and page arguments will be ignored.
//
// Unvetted record tokens will only be returned to admins.
type Inventory struct {
	State  string        `json:"state,omitempty"`
	Status RecordStatusT `json:"status,omitempty"`
	Page   uint32        `json:"page,omitempty"`
}

// InventoryReply is the reply to the Inventory command. The returned maps are
// map[status][]token where the status is the human readable record status
// defined by the RecordStatuses array in this package.
type InventoryReply struct {
	Unvetted map[string][]string `json:"unvetted"`
	Vetted   map[string][]string `json:"vetted"`
}

// Proof contains an inclusion proof for the digest in the merkle root. All
// digests are hex encoded SHA256 digests.
//
// The ExtraData field is used by certain types of proofs to include additional
// data that is required to validate the proof.
type Proof struct {
	Type       string   `json:"type"`
	Digest     string   `json:"digest"`
	MerkleRoot string   `json:"merkleroot"`
	MerklePath []string `json:"merklepath"`
	ExtraData  string   `json:"extradata"` // JSON encoded
}

// Timestamp contains all of the data required to verify that a piece of record
// data was timestamped onto the decred blockchain.
//
// All digests are hex encoded SHA256 digests. The merkle root can be found in
// the OP_RETURN of the specified DCR transaction.
//
// TxID, MerkleRoot, and Proofs will only be populated once the merkle root has
// been included in a DCR tx and the tx has 6 confirmations. The Data field
// will not be populated if the data has been censored.
type Timestamp struct {
	Data       string  `json:"data"` // JSON encoded
	Digest     string  `json:"digest"`
	TxID       string  `json:"txid"`
	MerkleRoot string  `json:"merkleroot"`
	Proofs     []Proof `json:"proofs"`
}

// Timestamps requests the timestamps for a specific record version. If the
// version is omitted, the timestamps for the most recent version will be
// returned.
type Timestamps struct {
	State   string `json:"state"`
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	RecordMetadata Timestamp `json:"recordmetadata"`

	// map[metadataID]Timestamp
	Metadata map[uint64]Timestamp `json:"metadata"`

	// map[filename]Timestamp
	Files map[string]Timestamp `json:"files"`
}

// UserRecords requests the tokens of all records submitted by a user. Unvetted
// record tokens are only returned to admins and the record author.
type UserRecords struct {
	UserID string `json:"userid"`
}

// UserRecordsReply is the reply to the UserRecords command.
type UserRecordsReply struct {
	Unvetted []string `json:"unvetted"`
	Vetted   []string `json:"vetted"`
}
