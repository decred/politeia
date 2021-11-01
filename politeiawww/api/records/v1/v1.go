// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/records/v1"

	// RoutePolicy returns the policy for the records API.
	RoutePolicy = "/policy"

	// RouteNew adds a new record.
	RouteNew = "/new"

	// RouteEdit edits a record.
	RouteEdit = "/edit"

	// RouteSetStatus sets the status of a record.
	RouteSetStatus = "/setstatus"

	// RouteDetails returns the details of a record.
	RouteDetails = "/details"

	// RouteTimestamps returns the timestamps of a record.
	RouteTimestamps = "/timestamps"

	// RouteRecords returns a batch of records.
	RouteRecords = "/records"

	// RouteInventory returns the tokens of the records in the inventory,
	// categorized by record state and record status.
	RouteInventory = "/inventory"

	// RouteInventoryOrdered returns a page of record tokens ordered by the
	// timestamp of their most recent status change from newest to oldest.
	RouteInventoryOrdered = "/inventoryordered"

	// RouteUserRecords returnes the tokens of all records submitted by a user.
	RouteUserRecords = "/userrecords"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeInputInvalid is returned when there is an error
	// while prasing a command payload.
	ErrorCodeInputInvalid ErrorCodeT = 1

	// ErrorCodeFilesEmpty is returned when record's files are
	// empty.
	ErrorCodeFilesEmpty ErrorCodeT = 2

	// ErrorCodeFileNameInvalid is returned when a file name is
	// invalid.
	ErrorCodeFileNameInvalid ErrorCodeT = 3

	// ErrorCodeFileNameDuplicate is returned when a file name is
	// a duplicate.
	ErrorCodeFileNameDuplicate ErrorCodeT = 4

	// ErrorCodeFileMIMETypeInvalid is returned when a file MIME type
	// is invalid.
	ErrorCodeFileMIMETypeInvalid ErrorCodeT = 5

	// ErrorCodeFileMIMETypeUnsupported is returned when a file MIME
	// type is unsupported.
	ErrorCodeFileMIMETypeUnsupported ErrorCodeT = 6

	// ErrorCodeFileDigestInvalid is returned when an invalid file
	// digest found.
	ErrorCodeFileDigestInvalid ErrorCodeT = 7

	// ErrorCodeFilePayloadInvalid is returned when an invalid file
	// payload found.
	ErrorCodeFilePayloadInvalid ErrorCodeT = 8

	// ErrorCodeMetadataStreamIDInvalid is returned a metadata stream
	// ID is invalid.
	ErrorCodeMetadataStreamIDInvalid ErrorCodeT = 9

	// ErrorCodePublicKeyInvalid is returned when a public key is not
	// a valid hex encoded, Ed25519 public key.
	ErrorCodePublicKeyInvalid ErrorCodeT = 10

	// ErrorCodeSignatureInvalid is returned when a signature is not
	// a valid hex encoded, Ed25519 signature or when the signature is
	// wrong.
	ErrorCodeSignatureInvalid ErrorCodeT = 11

	// ErrorCodeRecordTokenInvalid is returned when a record token is
	// invalid.
	ErrorCodeRecordTokenInvalid ErrorCodeT = 12

	// ErrorCodeRecordNotFound is returned when a record is not found.
	ErrorCodeRecordNotFound ErrorCodeT = 13

	// ErrorCodeRecordLocked is returned when a record is locked.
	ErrorCodeRecordLocked ErrorCodeT = 14

	// ErrorCodeNoRecordChanges is retuned when no record changes found.
	ErrorCodeNoRecordChanges ErrorCodeT = 15

	// ErrorCodeRecordStateInvalid is returned when a record state is
	// invalid.
	ErrorCodeRecordStateInvalid ErrorCodeT = 16

	// ErrorCodeRecordStatusInvalid is returned when a record status is
	// invalid.
	ErrorCodeRecordStatusInvalid ErrorCodeT = 17

	// ErrorCodeStatusChangeInvalid is returned when a record status change
	// is invalid.
	ErrorCodeStatusChangeInvalid ErrorCodeT = 18

	// ErrorCodeStatusReasonNotFound is returned when a record status change
	// reason is not found.
	ErrorCodeStatusReasonNotFound ErrorCodeT = 19

	// ErrorCodePageSizeExceeded is returned when the request's page size
	// exceeds the maximum page size of the request.
	ErrorCodePageSizeExceeded ErrorCodeT = 20

	// ErrorCodeLast is used by unit tests to verify that all error codes have
	// a human readable entry in the ErrorCodes map. This error will never be
	// returned.
	ErrorCodeLast ErrorCodeT = 21
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                 "error invalid",
		ErrorCodeInputInvalid:            "input invalid",
		ErrorCodeFilesEmpty:              "files are empty",
		ErrorCodeFileNameInvalid:         "file name invalid",
		ErrorCodeFileNameDuplicate:       "file name duplicate",
		ErrorCodeFileMIMETypeInvalid:     "file mime type invalid",
		ErrorCodeFileMIMETypeUnsupported: "file mime type unsupported",
		ErrorCodeFileDigestInvalid:       "file digest invalid",
		ErrorCodeFilePayloadInvalid:      "file payload invalid",
		ErrorCodeMetadataStreamIDInvalid: "metadata stream id invalid",
		ErrorCodePublicKeyInvalid:        "public key invalid",
		ErrorCodeSignatureInvalid:        "signature invalid",
		ErrorCodeRecordTokenInvalid:      "record token invalid",
		ErrorCodeRecordNotFound:          "record not found",
		ErrorCodeRecordLocked:            "record locked",
		ErrorCodeNoRecordChanges:         "no record changes",
		ErrorCodeRecordStateInvalid:      "record state invalid",
		ErrorCodeRecordStatusInvalid:     "record status invalid",
		ErrorCodeStatusChangeInvalid:     "status change invalid",
		ErrorCodeStatusReasonNotFound:    "status reason not found",
		ErrorCodePageSizeExceeded:        "page size exceeded",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
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

// Policy requests the policy settings for the records API.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
type PolicyReply struct {
	RecordsPageSize   uint32 `json:"recordspagesize"`
	InventoryPageSize uint32 `json:"inventorypagesize"`
}

// RecordStateT represents the state of a record.
type RecordStateT uint32

const (
	// RecordStateInvalid is an invalid record state.
	RecordStateInvalid RecordStateT = 0

	// RecordStateUnvetted indicates a record has not been made public.
	RecordStateUnvetted RecordStateT = 1

	// RecordStateVetted indicates a record has been made public.
	RecordStateVetted RecordStateT = 2

	// RecordStateLast unit test only.
	RecordStateLast RecordStateT = 3
)

var (
	// RecordStates contains the human readable record states.
	RecordStates = map[RecordStateT]string{
		RecordStateInvalid:  "invalid",
		RecordStateUnvetted: "unvetted",
		RecordStateVetted:   "vetted",
	}
)

// RecordStatusT represents the status of a record.
type RecordStatusT uint32

const (
	// RecordStatusInvalid is an invalid status code.
	RecordStatusInvalid RecordStatusT = 0

	// RecordStatusUnreviewed indicates a record has not been made
	// public yet. The state of an unreviewed record will always be
	// unvetted.
	RecordStatusUnreviewed RecordStatusT = 1

	// RecordStatusPublic indicates a record has been made public. The
	// state of a public record will always be vetted.
	RecordStatusPublic RecordStatusT = 2

	// RecordStatusCensored indicates a record has been censored. A
	// censored record is locked from any further updates and all
	// record content is permanently deleted. A censored record can
	// have a state of either unvetted or vetted.
	RecordStatusCensored RecordStatusT = 3

	// RecordStatusArchived indicates a record has been archived. An
	// archived record is locked from any further updates. An archived
	// record have a state of either unvetted or vetted.
	RecordStatusArchived RecordStatusT = 4

	// RecordStatusLast unit test only.
	RecordStatusLast RecordStatusT = 5
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
	PluginID string `json:"pluginid"`
	StreamID uint32 `json:"streamid"`
	Payload  string `json:"payload"` // JSON encoded
}

// CensorshipRecord contains cryptographic proof that a record was accepted for
// review by the server. The proof is verifiable by the client.
type CensorshipRecord struct {
	// Token is a random censorship token that is generated by the
	// server. It serves as a unique identifier for the record.
	Token string `json:"token"`

	// Merkle is the ordered merkle root of all files in the record.
	Merkle string `json:"merkle"`

	// Signature is the server signature of the Merkle+Token.
	Signature string `json:"signature"`
}

// Record represents a record and all of its content.
type Record struct {
	State     RecordStateT     `json:"state"`     // Record state
	Status    RecordStatusT    `json:"status"`    // Record status
	Version   uint32           `json:"version"`   // Version of this record
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
	Version   uint32        `json:"version"`
	Status    RecordStatusT `json:"status"`
	Reason    string        `json:"reason,omitempty"`
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
	Token     string        `json:"token"`
	Version   uint32        `json:"version"`
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
// If no version is specified then the most recent version will be returned.
type Details struct {
	Token   string `json:"token"`
	Version uint32 `json:"version,omitempty"`
}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	Record Record `json:"record"`
}

// Proof contains an inclusion proof for the digest in the merkle root. All
// digests are hex encoded SHA256 digests.
//
// The ExtraData field is used by certain types of proofs to include
// additional data that is required to validate the proof.
type Proof struct {
	Type       string   `json:"type"`
	Digest     string   `json:"digest"`
	MerkleRoot string   `json:"merkleroot"`
	MerklePath []string `json:"merklepath"`
	ExtraData  string   `json:"extradata"` // JSON encoded
}

// Timestamp contains all of the data required to verify that a piece of
// record data was timestamped onto the decred blockchain.
//
// All digests are hex encoded SHA256 digests. The merkle root can be found
// in the OP_RETURN of the specified DCR transaction.
//
// TxID, MerkleRoot, and Proofs will only be populated once the merkle root
// has been included in a DCR tx and the tx has 6 confirmations. The Data
// field will not be populated if the data has been censored.
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
	Token   string `json:"token"`
	Version uint32 `json:"version,omitempty"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	RecordMetadata Timestamp `json:"recordmetadata"`

	// map[pluginID]map[streamID]Timestamp
	Metadata map[string]map[uint32]Timestamp `json:"metadata"`

	// map[filename]Timestamp
	Files map[string]Timestamp `json:"files"`
}

const (
	// RecordsPageSize is the maximum number of records that can be
	// requested in a Records request.
	RecordsPageSize = 5
)

// RecordRequest is used to requests select content from a record. The latest
// version of the record is returned. By default, all record files will be
// stripped from the record before being returned.
//
// Filenames can be used to request specific files. If filenames is empty than
// no record files will be returned.
type RecordRequest struct {
	Token     string   `json:"token"`
	Filenames []string `json:"filenames,omitempty"`
}

// Records requests a batch of records. This route should be used when the
// client only requires select content from the record. The Details command
// should be used when the full record content is required. Unvetted record
// files are only returned to admins and the author.
type Records struct {
	Requests []RecordRequest `json:"requests"`
}

// RecordsReply is the reply to the Records command. Any tokens that did not
// correspond to a record will not be included in the reply.
//
// **Note** partial record's merkle root is not verifiable - when generating
// the record's merkle all files must be present.
type RecordsReply struct {
	Records map[string]Record `json:"records"` // [token]Record
}

const (
	// InventoryPageSize is the number of tokens that will be returned
	// per page for all inventory commands.
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
	State  RecordStateT  `json:"state,omitempty"`
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

// InventoryOrdered requests a page of record tokens ordered by the timestamp
// of their most recent status change from newest to oldest. The reply will
// include tokens for all record statuses. Unvetted tokens will only be
// returned to admins.
type InventoryOrdered struct {
	State RecordStateT `json:"state"`
	Page  uint32       `json:"page"`
}

// InventoryOrderedReply is the reply to the InventoryOrdered command.
type InventoryOrderedReply struct {
	Tokens []string `json:"tokens"`
}

// UserRecords requests the tokens of all records submitted by a user.
// Unvetted record tokens are only returned to admins and the record author.
type UserRecords struct {
	UserID string `json:"userid"`
}

// UserRecordsReply is the reply to the UserRecords command.
type UserRecordsReply struct {
	Unvetted []string `json:"unvetted"`
	Vetted   []string `json:"vetted"`
}
