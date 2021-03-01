// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"errors"
	"fmt"
	"regexp"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
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

	// ErrRecordLocked is returned when a record status is one that
	// does not allow any further changes.
	ErrRecordLocked = errors.New("record is locked")

	// ErrJournalsNotReplayed is returned when the journals have not
	// been replayed and the subsequent code expect it to be replayed.
	ErrJournalsNotReplayed = errors.New("journals have not been replayed")

	// ErrPluginInvalid is emitted when an invalid plugin ID is used.
	ErrPluginInvalid = errors.New("plugin invalid")

	// ErrPluginCmdInvalid is emitted when an invalid plugin command is
	// used.
	ErrPluginCmdInvalid = errors.New("plugin command invalid")

	// ErrPluginActionInvalid is emitted when an invalid plugin action
	// is used. See PluginActionRead and PluginActionWrite for valid
	// plugin actions.
	ErrPluginActionInvalid = errors.New("plugin action invalid")

	// Plugin names must be all lowercase letters and have a length of <20
	PluginRE = regexp.MustCompile(`^[a-z]{1,20}$`)
)

// ContentVerificationError is returned when a submitted record contains
// unacceptable file formats or corrupt data.
type ContentVerificationError struct {
	ErrorCode    v1.ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (c ContentVerificationError) Error() string {
	return fmt.Sprintf("%v: %v", v1.ErrorStatus[c.ErrorCode], c.ErrorContext)
}

// File represents a record file.
type File struct {
	Name    string `json:"name"`    // Basename of the file
	MIME    string `json:"mime"`    // MIME type
	Digest  string `json:"digest"`  // SHA256 of decoded Payload
	Payload string `json:"payload"` // base64 encoded file
}

// MDStatusT represents the status of a backend record.
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

// Error satisfies the error interface.
func (s StateTransitionError) Error() string {
	return fmt.Sprintf("invalid record status transition %v (%v) -> %v (%v)",
		s.From, MDStatus[s.From], s.To, MDStatus[s.To])
}

// RecordMetadata is the metadata of a record.
const VersionRecordMD = 1

// RecordMetadata represents metadata that is created by the backend on record
// submission and updates.
type RecordMetadata struct {
	Version   uint64    `json:"version"`   // Version of the scruture
	Iteration uint64    `json:"iteration"` // Iteration count of record
	Status    MDStatusT `json:"status"`    // Current status of the record
	Merkle    string    `json:"merkle"`    // Merkle root of all files in record
	Timestamp int64     `json:"timestamp"` // Last updated
	Token     string    `json:"token"`     // Record authentication token, hex encoded
}

// MetadataStream describes a single metada stream.
type MetadataStream struct {
	PluginID string `json:"pluginid,omitempty"` // Plugin identity
	ID       uint64 `json:"id"`                 // Stream identity
	Payload  string `json:"payload"`            // String encoded metadata
}

// Record is a permanent Record that includes the submitted files, metadata and
// internal metadata.
type Record struct {
	RecordMetadata RecordMetadata   // Internal metadata
	Version        string           // Version of Files
	Metadata       []MetadataStream // User provided metadata
	Files          []File           // User provided files
}

// RecordRequest is used to requests a record. It gives the client granular
// control over what is returned. The only required field is the token. All
// other fields are optional.
//
// Version is used to request a specific version of a record. If no version is
// provided then the most recent version of the record will be returned.
//
// Filenames can be used to request specific files. If filenames is not empty
// then the specified files will be the only files returned.
//
// OmitAllFiles can be used to retrieve a record without any of the record
// files. This supersedes the filenames argument.
type RecordRequest struct {
	Token        []byte
	Version      string
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
	Token          string // Censorship token
	Version        string // Version of files
	RecordMetadata Timestamp
	Metadata       map[string]Timestamp // [metadataID]Timestamp
	Files          map[string]Timestamp // [filename]Timestamp
}

const (
	// PluginActionRead is provided to the backend methods that execute
	// plugin commands to indicate that the plugin command is a read
	// only command.
	PluginActionRead = "read"

	// PluginActionWrite is provided to the backend methods that execute
	// plugin commands to indicate that the plugin command writes data
	// to the backend. This allows the backend to prevent concurrent
	// writes to the record so that individual plugin implementations
	// do not need to worry about implementing logic to prevent race
	// conditions.
	PluginActionWrite = "write"
)

// PluginSettings are used to specify settings for a plugin at runtime.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings

	// Identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	Identity *identity.FullIdentity
}

// PluginError represents a plugin error that is caused by the user.
type PluginError struct {
	PluginID     string
	ErrorCode    int
	ErrorContext string
}

// Error satisfies the error interface.
func (e PluginError) Error() string {
	return fmt.Sprintf("plugin id '%v' error code %v",
		e.PluginID, e.ErrorCode)
}

const (
	// StateUnvetted is used to request the inventory of an unvetted
	// status.
	StateUnvetted = "unvetted"

	// StateVetted is used to request the inventory of a vetted status.
	StateVetted = "vetted"
)

// InventoryByStatus contains the tokens of the records in the inventory
// categorized by record state and record status. Each list contains a page of
// tokens that are sorted by the timestamp of the status change from newest to
// oldest.
type InventoryByStatus struct {
	Unvetted map[MDStatusT][]string
	Vetted   map[MDStatusT][]string
}

// Backend provides an API for creating and editing records. When a record is
// first submitted it is considered to be an unvetted, i.e. non-public, record.
// Once the status of the record is updated to a public status, the record is
// considered to be vetted.
type Backend interface {
	// Create new record
	New([]MetadataStream, []File) (*RecordMetadata, error)

	// Update unvetted record
	UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []MetadataStream,
		filesAdd []File, filesDel []string) (*Record, error)

	// Update vetted record
	UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []MetadataStream,
		filesAdd []File, filesDel []string) (*Record, error)

	// Update unvetted metadata
	UpdateUnvettedMetadata(token []byte, mdAppend,
		mdOverwrite []MetadataStream) error

	// Update vetted metadata
	UpdateVettedMetadata(token []byte, mdAppend,
		mdOverwrite []MetadataStream) error

	// Set unvetted record status
	SetUnvettedStatus(token []byte, s MDStatusT, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// Set vetted record status
	SetVettedStatus(token []byte, s MDStatusT, mdAppend,
		mdOverwrite []MetadataStream) (*Record, error)

	// Check if an unvetted record exists
	UnvettedExists(token []byte) bool

	// Check if a vetted record exists
	VettedExists(token []byte) bool

	// Get unvetted record
	GetUnvetted(token []byte, version string) (*Record, error)

	// Get vetted record
	GetVetted(token []byte, version string) (*Record, error)

	// Get a batch of unvetted records
	GetUnvettedBatch(reqs []RecordRequest) (map[string]Record, error)

	// Get a batch of vetted records
	GetVettedBatch(reqs []RecordRequest) (map[string]Record, error)

	// Get unvetted record timestamps
	GetUnvettedTimestamps(token []byte,
		version string) (*RecordTimestamps, error)

	// Get vetted record timestamps
	GetVettedTimestamps(token []byte,
		version string) (*RecordTimestamps, error)

	// Get record tokens categorized by MDStatusT
	InventoryByStatus(state string, s MDStatusT,
		pageSize, page uint32) (*InventoryByStatus, error)

	// Register an unvetted plugin with the backend
	RegisterUnvettedPlugin(Plugin) error

	// Register a vetted plugin with the backend
	RegisterVettedPlugin(Plugin) error

	// Perform any plugin setup that is required
	SetupUnvettedPlugin(pluginID string) error

	// Perform any plugin setup that is required
	SetupVettedPlugin(pluginID string) error

	// Execute a unvetted plugin command
	UnvettedPluginCmd(action string, token []byte, pluginID,
		cmd, payload string) (string, error)

	// Execute a vetted plugin command
	VettedPluginCmd(action string, token []byte, pluginID,
		cmd, payload string) (string, error)

	// Get unvetted plugins
	GetUnvettedPlugins() []Plugin

	// Get vetted plugins
	GetVettedPlugins() []Plugin

	// Inventory retrieves various record records
	//
	// This method has been DEPRECATED.
	Inventory(uint, uint, uint, bool, bool) ([]Record, []Record, error)

	// Plugin pass-through command
	//
	// This method has been DEPRECATED.
	Plugin(pluginID, cmd, cmdID, payload string) (string, error)

	// Obtain plugin settings
	//
	// This method has been DEPRECATED.
	GetPlugins() ([]Plugin, error)

	// Close performs cleanup of the backend
	Close()
}
