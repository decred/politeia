// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import "fmt"

const (
	// APIRoute is prefixed onto all routes in this package.
	APIRoute = "/v2"

	// RouteRecordNew creates a new record.
	RouteRecordNew = "/recordnew"

	// RouteRecordEdit edits a record.
	RouteRecordEdit = "/recordedit"

	// RouteRecordEditMetadata edits record's metadata.
	RouteRecordEditMetadata = "/recordeditmetadata"

	// RouteRecordSetStatus sets the status of a record.
	RouteRecordSetStatus = "/recordsetstatus"

	// RouteRecordTimestamps returns the record timestamps.
	RouteRecordTimestamps = "/recordtimestamps"

	// RouteRecords retrieves a page of records.
	RouteRecords = "/records"

	// RouteInventory returns the tokens of records in the inventory
	// categorized by record state and record status.
	RouteInventory = "/inventory"

	// RouteInventoryOrdered returns a page of record tokens ordered by the
	// timestamp of their most recent status change from newest to
	// oldest. The returned tokens will include all record statuses.
	RouteInventoryOrdered = "/inventoryordered"

	// RoutePluginWrite executes a plugin command that writes data.
	RoutePluginWrite = "/pluginwrite"

	// RoutePluginReads executes a read-only plugin command.
	RoutePluginReads = "/pluginreads"

	// RoutePluginInventory returns all registered plugins.
	RoutePluginInventory = "/plugininventory"

	// ChallengeSize is the size of a request challenge token in bytes.
	ChallengeSize = 32
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeRequestPayloadInvalid is returned when a request's payload
	// is invalid.
	ErrorCodeRequestPayloadInvalid ErrorCodeT = 1

	// ErrorCodeChallengeInvalid is returned when a challenge is invalid.
	ErrorCodeChallengeInvalid ErrorCodeT = 2

	// ErrorCodeMetadataStreamInvalid is returned when a metadata stream
	// is invalid.
	ErrorCodeMetadataStreamInvalid ErrorCodeT = 3

	// ErrorCodeMetadataStreamDuplicate is returned when a metadata stream
	// is a duplicate.
	ErrorCodeMetadataStreamDuplicate ErrorCodeT = 4

	// ErrorCodeFilesEmpty is returned when no files found.
	ErrorCodeFilesEmpty ErrorCodeT = 5

	// ErrorCodeFileNameInvalid is returned when a file name is invalid.
	ErrorCodeFileNameInvalid ErrorCodeT = 6

	// ErrorCodeFileNameDuplicate is returned when a file name is a duplicate.
	ErrorCodeFileNameDuplicate ErrorCodeT = 7

	// ErrorCodeFileDigestInvalid is returned when a file digest is invalid.
	ErrorCodeFileDigestInvalid ErrorCodeT = 8

	// ErrorCodeFilePayloadInvalid is returned when a file payload is invalid.
	ErrorCodeFilePayloadInvalid ErrorCodeT = 9

	// ErrorCodeFileMIMETypeInvalid is returned when a file MIME type is
	// invalid.
	ErrorCodeFileMIMETypeInvalid ErrorCodeT = 10

	// ErrorCodeFileMIMETypeUnsupported is returned when a file MIME type is
	// unsupoorted.
	ErrorCodeFileMIMETypeUnsupported ErrorCodeT = 11

	// ErrorCodeTokenInvalid is returned when a token is invalid.
	ErrorCodeTokenInvalid ErrorCodeT = 12

	// ErrorCodeRecordNotFound is returned when a record is not found.
	ErrorCodeRecordNotFound ErrorCodeT = 13

	// ErrorCodeRecordLocked is returned when a record is locked.
	ErrorCodeRecordLocked ErrorCodeT = 14

	// ErrorCodeNoRecordChanges is retuned when no record changes found.
	ErrorCodeNoRecordChanges ErrorCodeT = 15

	// ErrorCodeStatusChangeInvalid is returned when a record status change
	// is invalid.
	ErrorCodeStatusChangeInvalid ErrorCodeT = 16

	// ErrorCodePluginIDInvalid is returned when a plugin ID is invalid.
	ErrorCodePluginIDInvalid ErrorCodeT = 17

	// ErrorCodePluginCmdInvalid is returned when a plugin cmd is invalid.
	ErrorCodePluginCmdInvalid ErrorCodeT = 18

	// ErrorCodePageSizeExceeded is returned when the request's page size
	// exceeds the maximum page size of the request.
	ErrorCodePageSizeExceeded ErrorCodeT = 19

	// ErrorCodeRecordStateInvalid is returned when the provided state
	// does not match the record state.
	ErrorCodeRecordStateInvalid ErrorCodeT = 20

	// ErrorCodeRecordStatusInvalid is returned when a record status is
	// invalid.
	ErrorCodeRecordStatusInvalid ErrorCodeT = 21

	// ErrorCodeDuplicatePayload is returned when a duplicate payload is sent
	// to a plugin, where it tries to write data that already exists. Timestamp
	// data relies on the hash of the payload, therefore duplicate payloads are
	// not allowed since they will cause collisions.
	ErrorCodeDuplicatePayload ErrorCodeT = 22

	// ErrorCodeLast is used by unit tests to verify that all error codes have
	// a human readable entry in the ErrorCodes map. This error will never be
	// returned.
	ErrorCodeLast ErrorCodeT = 23
)

var (
	// ErrorCodes contains the human readable error codes.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                 "invalid error",
		ErrorCodeRequestPayloadInvalid:   "request payload invalid",
		ErrorCodeChallengeInvalid:        "invalid challenge",
		ErrorCodeMetadataStreamInvalid:   "metadata stream invalid",
		ErrorCodeMetadataStreamDuplicate: "metadata stream duplicate",
		ErrorCodeFilesEmpty:              "files are empty",
		ErrorCodeFileNameInvalid:         "file name invalid",
		ErrorCodeFileNameDuplicate:       "file name is a duplicate",
		ErrorCodeFileDigestInvalid:       "file digest invalid",
		ErrorCodeFilePayloadInvalid:      "file payload invalid",
		ErrorCodeFileMIMETypeInvalid:     "file mime type invalid",
		ErrorCodeFileMIMETypeUnsupported: "file mime type not supported",
		ErrorCodeTokenInvalid:            "token invalid",
		ErrorCodeRecordNotFound:          "record not found",
		ErrorCodeRecordLocked:            "record is locked",
		ErrorCodeNoRecordChanges:         "no record changes",
		ErrorCodeStatusChangeInvalid:     "status change invalid",
		ErrorCodePluginIDInvalid:         "pluguin id invalid",
		ErrorCodePluginCmdInvalid:        "plugin cmd invalid",
		ErrorCodePageSizeExceeded:        "page size exceeded",
		ErrorCodeRecordStateInvalid:      "record state invalid",
		ErrorCodeRecordStatusInvalid:     "record status invalid",
		ErrorCodeDuplicatePayload:        "duplicate payload",
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
// a plugin error. The error code will be specific to the plugin.
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

// RecordStateT represents the state of a record.
type RecordStateT uint32

const (
	// RecordStateInvalid is an invalid record state.
	RecordStateInvalid RecordStateT = 0

	// RecordStateUnvetted indicates a record has not been made public.
	RecordStateUnvetted RecordStateT = 1

	// RecordStateVetted indicates a record has been made public.
	RecordStateVetted RecordStateT = 2

	// RecordStateLast is used for unit test validation of human readable
	// errors.
	RecordStateLast = 3
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
	// record can have a state of either unvetted or vetted.
	RecordStatusArchived RecordStatusT = 4

	// RecordStatusLast is used for unit test validation of human readable
	// errors.
	RecordStatusLast = 5
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

// MetadataStream describes a single metada stream.
type MetadataStream struct {
	PluginID string `json:"pluginid"` // Plugin identity
	StreamID uint32 `json:"streamid"` // Stream identity
	Payload  string `json:"payload"`  // JSON encoded metadata
}

// File represents a record file.
type File struct {
	Name    string `json:"name"`    // Basename of the file
	MIME    string `json:"mime"`    // MIME type
	Digest  string `json:"digest"`  // SHA256 of decoded Payload
	Payload string `json:"payload"` // Base64 encoded file payload
}

const (
	// TokenSize is the size of a censorship record token in bytes.
	TokenSize = 8

	// ShortTokenLength is the length, in characters, of a hex encoded
	// token that has been shortened to improved UX. Short tokens can
	// be used to retrieve record data but cannot be used on any routes
	// that write record data. 7 characters was chosen to match the git
	// abbreviated commitment hash size.
	ShortTokenLength = 7
)

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

// Record represents a record and all of its contents.
type Record struct {
	State     RecordStateT     `json:"state"`     // Record state
	Status    RecordStatusT    `json:"status"`    // Record status
	Version   uint32           `json:"version"`   // Version of this record
	Timestamp int64            `json:"timestamp"` // Last update
	Metadata  []MetadataStream `json:"metadata"`
	Files     []File           `json:"files"`

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// RecordNew creates a new record. It must include all files that are part of
// the record and it may contain optional metadata.
type RecordNew struct {
	Challenge string           `json:"challenge"` // Random challenge
	Metadata  []MetadataStream `json:"metadata,omitempty"`
	Files     []File           `json:"files"`
}

// RecordNewReply is the reply to the RecordNew command.
type RecordNewReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
}

// RecordEdit edits and existing record.
//
// MDAppend appends metadata to a metadata stream. MDOverwrite overwrites a
// metadata stream. If the metadata stream does not exist yet for either of
// these arguments, a new metadata stream will be created.
//
// FilesAdd should include files that are being modified or added. FilesDel
// is the filenames of existing files that will be deleted. If a filename is
// provided in FilesDel that does not correspond to an actual record file, it
// will be ignored.
type RecordEdit struct {
	Challenge   string           `json:"challenge"` // Random challenge
	Token       string           `json:"token"`     // Censorship token
	MDAppend    []MetadataStream `json:"mdappend,omitempty"`
	MDOverwrite []MetadataStream `json:"mdoverwrite,omitempty"`
	FilesAdd    []File           `json:"filesadd,omitempty"`
	FilesDel    []string         `json:"filesdel,omitempty"`
}

// RecordEditReply is the reply to the RecordEdit command.
type RecordEditReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
}

// RecordEditMetadata edits the metadata of a record.
//
// MDAppend appends metadata to a metadata stream. MDOverwrite overwrites a
// metadata stream. If the metadata stream does not exist yet for either of
// these arguments, a new metadata stream will be created.
type RecordEditMetadata struct {
	Challenge   string           `json:"challenge"` // Random challenge
	Token       string           `json:"token"`     // Censorship token
	MDAppend    []MetadataStream `json:"mdappend,omitempty"`
	MDOverwrite []MetadataStream `json:"mdoverwrite,omitempty"`
}

// RecordEditMetadataReply is the reply to the RecordEditMetadata command.
type RecordEditMetadataReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
}

// RecordSetStatus sets the status of a record.
//
// MDAppend appends metadata to a metadata stream. MDOverwrite overwrites a
// metadata stream. If the metadata stream does not exist yet for either of
// these arguments, a new metadata stream will be created.
type RecordSetStatus struct {
	Challenge   string           `json:"challenge"` // Random challenge
	Token       string           `json:"token"`     // Censorship token
	Status      RecordStatusT    `json:"status"`
	MDAppend    []MetadataStream `json:"mdappend,omitempty"`
	MDOverwrite []MetadataStream `json:"mdoverwrite,omitempty"`
}

// RecordSetStatusReply is the reply to the RecordSetStatus command.
type RecordSetStatusReply struct {
	Response string `json:"response"` // Challenge response
	Record   Record `json:"record"`
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
// content was timestamped onto the decred blockchain.
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

// RecordTimestamps requests the timestamps for a record. If a version is not
// included the most recent version will be returned.
type RecordTimestamps struct {
	Challenge string `json:"challenge"`         // Random challenge
	Token     string `json:"token"`             // Censorship token
	Version   uint32 `json:"version,omitempty"` // Record version
}

// RecordTimestampsReply is the reply ot the RecordTimestamps command.
type RecordTimestampsReply struct {
	Response       string    `json:"response"` // Challenge response
	RecordMetadata Timestamp `json:"recordmetadata"`

	// map[pluginID]map[streamID]Timestamp
	Metadata map[string]map[uint32]Timestamp `json:"metadata"`

	// map[filename]Timestamp
	Files map[string]Timestamp `json:"files"`
}

const (
	// RecordsPageSize is the maximum number of records that can be
	// requested using the Records commands.
	RecordsPageSize uint32 = 5
)

// RecordRequest is used to request a record. It gives the caller granular
// control over what is returned. The only required field is the token. All
// other fields are optional. All record files are returned by default unless
// one of the file arguments is provided.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is provided
// then the specified files will be the only files that are returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
type RecordRequest struct {
	Token        string   `json:"token"`
	Version      uint32   `json:"version,omitempty"`
	Filenames    []string `json:"filenames,omitempty"`
	OmitAllFiles bool     `json:"omitallfiles,omitempty"`
}

// Records retrieves a record. If no version is provided the most recent
// version will be returned.
type Records struct {
	Challenge string          `json:"challenge"` // Random challenge
	Requests  []RecordRequest `json:"requests"`
}

// RecordsReply is the reply to the Records command. If a record was not found
// or an error occurred while retrieving it the token will not be included in
// the returned map.
//
// **Note** partial record's merkle root is not verifiable - when generating
// the record's merkle all files must be present.
type RecordsReply struct {
	Response string            `json:"response"` // Challenge response
	Records  map[string]Record `json:"records"`  // [token]Record
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
// If no status is provided then a page of tokens for all statuses will be
// returned. All other arguments will be ignored.
type Inventory struct {
	Challenge string        `json:"challenge"` // Random challenge
	State     RecordStateT  `json:"state,omitempty"`
	Status    RecordStatusT `json:"status,omitempty"`
	Page      uint32        `json:"page,omitempty"`
}

// InventoryReply is the reply to the Inventory command. The map keys are the
// human readable record statuses defined by the RecordStatuses array.
type InventoryReply struct {
	Response string              `json:"response"` // Challenge response
	Unvetted map[string][]string `json:"unvetted"` // [status][]token
	Vetted   map[string][]string `json:"vetted"`   // [status][]token
}

// InventoryOrdered requests a page of record tokens ordered by the timestamp
// of their most recent status change from newest to oldest. The reply will
// include tokens for all record statuses.
type InventoryOrdered struct {
	Challenge string       `json:"challenge"` // Random challenge
	State     RecordStateT `json:"state"`
	Page      uint32       `json:"page"`
}

// InventoryOrderedReply is the reply to the InventoryOrdered command.
type InventoryOrderedReply struct {
	Response string   `json:"response"` // Challenge response
	Tokens   []string `json:"tokens"`
}

// PluginCmd represents plugin command and the command payload. A token is
// required for all plugin writes, but is optional for reads.
type PluginCmd struct {
	Token   string `json:"token,omitempty"`   // Censorship token
	ID      string `json:"id"`                // Plugin identifier
	Command string `json:"command"`           // Plugin command
	Payload string `json:"payload,omitempty"` // Command payload
}

// PluginWrite executes a plugin command that writes data.
type PluginWrite struct {
	Challenge string    `json:"challenge"` // Random challenge
	Cmd       PluginCmd `json:"cmd"`
}

// PluginWriteReply is the reply to the PluginWrite command.
type PluginWriteReply struct {
	Response string `json:"response"` // Challenge response
	Payload  string `json:"payload"`  // Response payload
}

// PluginReads executes a batch of read only plugin commands.
type PluginReads struct {
	Challenge string      `json:"challenge"` // Random challenge
	Cmds      []PluginCmd `json:"cmds"`
}

// PluginCmdReply is the reply to an individual plugin command that is part of
// a batch of plugin commands. The error will be included in the reply if one
// was encountered.
type PluginCmdReply struct {
	Token   string `json:"token"`   // Censorship token
	ID      string `json:"id"`      // Plugin identifier
	Command string `json:"command"` // Plugin command
	Payload string `json:"payload"` // Response payload

	// UserError will be populated if a user error is encountered prior
	// to plugin command execution.
	UserError *UserErrorReply `json:"usererror,omitempty"`

	// PluginError will be populated if a plugin error occurred during
	// plugin command execution.
	PluginError *PluginErrorReply `json:"pluginerror,omitempty"`
}

// PluginReadsReply is the reply to the PluginReads command.
type PluginReadsReply struct {
	Response string           `json:"response"` // Challenge response
	Replies  []PluginCmdReply `json:"replies"`
}

// PluginSetting is a structure that holds key/value pairs of a plugin setting.
type PluginSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          `json:"id"`
	Settings []PluginSetting `json:"settings"`
}

// PluginInventory retrieves all active plugins and their settings.
type PluginInventory struct {
	Challenge string `json:"challenge"` // Random challenge
}

// PluginInventoryReply returns all plugins and their settings.
type PluginInventoryReply struct {
	Response string   `json:"response"` // Challenge response
	Plugins  []Plugin `json:"plugins"`
}
