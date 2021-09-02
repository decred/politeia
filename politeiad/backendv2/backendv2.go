// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backendv2

import (
	"errors"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

var (
	// ErrShutdown is returned when the backend is shutdown.
	ErrShutdown = errors.New("backend is shutdown")

	// ErrTokenInvalid is returned when a token is invalid.
	ErrTokenInvalid = errors.New("token is invalid")

	// ErrRecordNotFound is returned when a record is not found.
	ErrRecordNotFound = errors.New("record not found")

	// ErrRecordLocked is returned when a record is attempted to be
	// updated but the record status does not allow further updates.
	ErrRecordLocked = errors.New("record is locked")

	// ErrNoRecordChanges is returned when a record update does not
	// contain any changes.
	ErrNoRecordChanges = errors.New("no record changes")

	// ErrPluginIDInvalid is returned when a invalid plugin ID is used.
	ErrPluginIDInvalid = errors.New("plugin id invalid")

	// ErrPluginCmdInvalid is returned when a invalid plugin command is
	// used.
	ErrPluginCmdInvalid = errors.New("plugin command invalid")

	// ErrDuplicatePayload is returned when a duplicate payload is sent to
	// a plugin, where it tries to write data that already exists. Timestamp
	// data relies on the hash of the payload, therefore duplicate payloads
	// are not allowed since they will cause collisions.
	ErrDuplicatePayload = errors.New("duplicate payload")
)

// StateT represents the state of a record.
type StateT uint32

const (
	// StateInvalid is an invalid record state.
	StateInvalid StateT = 0

	// StateUnvetted indicates a record has not been made public.
	StateUnvetted StateT = 1

	// StateVetted indicates a record has been made public.
	StateVetted StateT = 2

	// StateLast used for unit test only.
	StateLast StateT = 3
)

var (
	// States contains the human readable record states.
	States = map[StateT]string{
		StateInvalid:  "invalid",
		StateUnvetted: "unvetted",
		StateVetted:   "vetted",
	}
)

// StatusT represents the status of a record.
type StatusT uint32

const (
	// StatusInvalid is an invalid status code.
	StatusInvalid StatusT = 0

	// StatusUnreviewed indicates a record has not been made public
	// yet. The state of an unreviewed record will always be unvetted.
	StatusUnreviewed StatusT = 1

	// StatusPublic indicates a record has been made public. The state
	// of a public record will always be vetted.
	StatusPublic StatusT = 2

	// StatusCensored indicates a record has been censored. A censored
	// record is locked from any further updates and all record content
	// is permanently deleted. A censored record can have a state of
	// either unvetted or vetted.
	StatusCensored StatusT = 3

	// StatusArchived indicates a record has been archived. An archived
	// record is locked from any further updates. An archived record
	// have a state of either unvetted or vetted.
	StatusArchived StatusT = 4

	// StatusLast is used for unit test validation of human readable
	// errors.
	StatusLast StatusT = 5
)

var (
	// Statuses contains the human readable record statuses.
	Statuses = map[StatusT]string{
		StatusInvalid:    "invalid",
		StatusUnreviewed: "unreviewed",
		StatusPublic:     "public",
		StatusCensored:   "censored",
		StatusArchived:   "archived",
	}
)

// StatusTransitionError indicates an invalid record status transition.
type StatusTransitionError struct {
	From StatusT
	To   StatusT
}

// Error satisfies the error interface.
func (s StatusTransitionError) Error() string {
	return fmt.Sprintf("invalid record status transition %v (%v) -> %v (%v)",
		Statuses[s.From], s.From, Statuses[s.To], s.To)
}

// RecordMetadata represents metadata that is created by the backend on record
// submission and updates.
//
// The record version is incremented anytime the record files are updated. The
// record iteration is incremented anytime record files, metadata, or the
// record status are updated.
type RecordMetadata struct {
	Token     string  `json:"token"`     // Record identifier, hex encoded
	Version   uint32  `json:"version"`   // Record version
	Iteration uint32  `json:"iteration"` // Record iteration
	State     StateT  `json:"state"`     // Unvetted or vetted
	Status    StatusT `json:"status"`    // Record status
	Timestamp int64   `json:"timestamp"` // Last updated
	Merkle    string  `json:"merkle"`    // Merkle root of record files
}

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

// Record is a permanent record that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata   `json:"recordmetadata"`
	Metadata       []MetadataStream `json:"metadata"`
	Files          []File           `json:"files"`
}

// ContentErrorCodeT represents a record content error.
type ContentErrorCodeT uint32

const (
	ContentErrorInvalid                 ContentErrorCodeT = 0
	ContentErrorMetadataStreamInvalid   ContentErrorCodeT = 1
	ContentErrorMetadataStreamDuplicate ContentErrorCodeT = 2
	ContentErrorFilesEmpty              ContentErrorCodeT = 3
	ContentErrorFileNameInvalid         ContentErrorCodeT = 4
	ContentErrorFileNameDuplicate       ContentErrorCodeT = 5
	ContentErrorFileDigestInvalid       ContentErrorCodeT = 6
	ContentErrorFilePayloadInvalid      ContentErrorCodeT = 7
	ContentErrorFileMIMETypeInvalid     ContentErrorCodeT = 8
	ContentErrorFileMIMETypeUnsupported ContentErrorCodeT = 9
)

// ContentError is returned when the content of a record does not pass
// validation.
type ContentError struct {
	ErrorCode    ContentErrorCodeT `json:"errorcode"`
	ErrorContext string            `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e ContentError) Error() string {
	return fmt.Sprintf("content error code: %v", e.ErrorCode)
}

// RecordRequest is used to request a record. It gives the caller granular
// control over what is returned. The only required field is the token. All
// other fields are optional. All record files are returned by default unless
// one of the file arguments is provided.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is not empty
// then the specified files will be the only files that are returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
type RecordRequest struct {
	Token        []byte
	Version      uint32
	Filenames    []string
	OmitAllFiles bool
}

// Proof contains an inclusion proof for the digest in the merkle root. All
// digests are hex encoded SHA256 digests.
//
// The ExtraData field is used by certain types of proofs to include additional
// data that is required to validate the proof.
type Proof struct {
	Type       string
	Digest     string
	MerkleRoot string
	MerklePath []string
	ExtraData  string // JSON encoded
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
	Data       string // JSON encoded
	Digest     string
	TxID       string
	MerkleRoot string
	Proofs     []Proof
}

// RecordTimestamps contains a Timestamp for all record data.
type RecordTimestamps struct {
	RecordMetadata Timestamp

	Metadata map[string]map[uint32]Timestamp // [pluginID][streamID]Timestamp
	Files    map[string]Timestamp            // map[filename]Timestamp
}

// Inventory contains the tokens of records in the inventory categorized by
// record state and record status. Tokens are sorted by the timestamp of the
// status change from newest to oldest.
type Inventory struct {
	Unvetted map[StatusT][]string
	Vetted   map[StatusT][]string
}

// PluginSetting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string
	Settings []PluginSetting

	// Identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	Identity *identity.FullIdentity
}

// PluginError represents an error that occurred during plugin execution that
// was caused by the user.
type PluginError struct {
	PluginID     string
	ErrorCode    uint32
	ErrorContext string
}

// Error satisfies the error interface.
func (e PluginError) Error() string {
	return fmt.Sprintf("%v plugin error code %v",
		e.PluginID, e.ErrorCode)
}

// Backend provides an API for interacting with records in the backend.
type Backend interface {
	// RecordNew creates a new record.
	RecordNew([]MetadataStream, []File) (*Record, error)

	// RecordEdit edits an existing record.
	RecordEdit(token []byte, mdAppend, mdOverwrite []MetadataStream,
		filesAdd []File, filesDel []string) (*Record, error)

	// RecordEditMetadata edits the metadata of a record without
	// editing any record files.
	RecordEditMetadata(token []byte, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// RecordSetStatus sets the status of a record.
	RecordSetStatus(token []byte, s StatusT, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// RecordExists returns whether a record exists.
	RecordExists(token []byte) bool

	// RecordTimestamps returns the timestamps for a record. If no
	// version is provided then timestamps for the most recent version
	// will be returned.
	RecordTimestamps(token []byte, version uint32) (*RecordTimestamps, error)

	// Records retreives a batch of records. If a record is not found
	// then it is simply not included in the returned map. An error is
	// not returned.
	Records(reqs []RecordRequest) (map[string]Record, error)

	// Inventory returns the tokens of records in the inventory
	// categorized by record state and record status. The tokens are
	// ordered by the timestamp of their most recent status change,
	// sorted from newest to oldest.
	//
	// The state, status, and page arguments can be provided to request
	// a specific page of record tokens.
	//
	// If no status is provided then the most recent page of tokens for
	// all statuses will be returned. All other arguments are ignored.
	Inventory(state StateT, status StatusT, pageSize,
		pageNumber uint32) (*Inventory, error)

	// InventoryOrdered returns a page of record tokens ordered by the
	// timestamp of their most recent status change from newest to
	// oldest. The returned tokens will include all record statuses.
	InventoryOrdered(s StateT, pageSize, pageNumber uint32) ([]string, error)

	// PluginRegister registers a plugin.
	PluginRegister(Plugin) error

	// PluginSetup performs any required plugin setup.
	PluginSetup(pluginID string) error

	// PluginRead executes a read-only plugin command.
	PluginRead(token []byte, pluginID, pluginCmd,
		payload string) (string, error)

	// PluginWrite executes a plugin command that writes data.
	PluginWrite(token []byte, pluginID, pluginCmd,
		payload string) (string, error)

	// PluginInventory returns all registered plugins.
	PluginInventory() []Plugin

	// Fsck performs a synchronous filesystem check that verifies
	// the coherency of record and plugin data and caches.
	Fsck() error

	// Close performs cleanup of the backend.
	Close()
}
