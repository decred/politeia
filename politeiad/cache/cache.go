// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cache

import (
	"errors"

	"github.com/jinzhu/gorm"
)

type RecordStatusT int

var (
	// ErrNoVersionRecord is emitted when no version record exists.
	ErrNoVersionRecord = errors.New("no version record")

	// ErrWrongVersion is emitted when the version record does not
	// match the implementation version.
	ErrWrongVersion = errors.New("wrong version")

	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrRecordNotFound is emitted when a cache record could not be
	// found.
	ErrRecordNotFound = errors.New("record not found")

	// ErrInvalidPlugin is emitted when an invalid plugin is used.
	ErrInvalidPlugin = errors.New("invalid plugin")

	// ErrDuplicatePlugin is emitted when the a plugin is registered
	// more than once.
	ErrDuplicatePlugin = errors.New("duplicate plugin")

	// ErrInvalidPluginCmd is emitted when an invalid plugin command
	// is used.
	ErrInvalidPluginCmd = errors.New("invalid plugin command")

	// ErrInvalidPluginCmdArgs is emitted when a plugin command is used
	// with invalid arguments.
	ErrInvalidPluginCmdArgs = errors.New("invalid plugin command arguments")
)

const (
	// Record status codes
	RecordStatusInvalid           RecordStatusT = 0 // Invalid status
	RecordStatusNotFound          RecordStatusT = 1 // Record not found
	RecordStatusNotReviewed       RecordStatusT = 2 // Record has not been reviewed
	RecordStatusCensored          RecordStatusT = 3 // Record has been censored
	RecordStatusPublic            RecordStatusT = 4 // Record is publicly visible
	RecordStatusUnreviewedChanges RecordStatusT = 5 // NotReviewed record that has been changed
	RecordStatusArchived          RecordStatusT = 6 // Public record that has been archived
)

// File describes an individual file that is part of the record.
type File struct {
	Name    string // Basename of the file
	MIME    string // MIME type
	Digest  string // SHA256 of decoded Payload
	Payload string // base64 encoded file
}

// MetadataStream identifies a metadata stream by its identity.
type MetadataStream struct {
	ID      uint64 // Stream identity
	Payload string // String encoded metadata
}

// CensorshipRecord contains the proof that a record was accepted for review.
// The proof is verifiable on the client side.  The Merkle field contains the
// ordered merkle root of all files in the record. The Token field contains a
// random censorship token that is signed by the server private key.  The token
// can be used on the client to verify the authenticity of the
// CensorshipRecord.
type CensorshipRecord struct {
	Token     string // Censorship token
	Merkle    string // Merkle root of record
	Signature string // Signature of merkle+token
}

// Record is an entire record and it's content.
type Record struct {
	Version          string           // Version of this record
	Status           RecordStatusT    // Current status
	Timestamp        int64            // Last update
	CensorshipRecord CensorshipRecord // Censorship record
	Metadata         []MetadataStream // Metadata streams
	Files            []File           // Files that make up the record
}

// InventoryStats is a summary of the number of records in the cache grouped
// by record status.  Only the latest version of each record is included.
type InventoryStats struct {
	Invalid           int // Number of invalid records
	NotReviewed       int // Number of unreviewed records
	Censored          int // Number of censored records
	Public            int // Number of public records
	UnreviewedChanges int // Number of unreviewed records with edits
	Archived          int // Number of archived records
}

// PluginCommand is used to execute a plugin command.  The reply payload
// contains the reply from politeiad, which is sometimes required by commands
// that write data to the cache.  The reply payload will be empty for commands
// that only read data from the cache.
type PluginCommand struct {
	ID             string // Plugin identifier
	Command        string // Command identifier
	CommandPayload string // Command payload
	ReplyPayload   string // Command reply payload
}

// PluginCommandReply is used to reply to a PluginCommand.
type PluginCommandReply struct {
	ID      string // Plugin identifier
	Command string // Command identifier
	Payload string // Actual command reply
}

// PluginSetting is a structure that holds key/value pairs of a plugin setting.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings
}

// PluginDriver describes the common set of methods that the cache uses to
// build and maintain the cache for a plugin.
//
// All cache plugins must implement the PluginDriver interface.
type PluginDriver interface {
	// Check that the correct plugin version is being used
	CheckVersion() error

	// Setup the plugin tables
	Setup() error

	// Build the plugin tables from scratch. The given payload should
	// provide all data necessary to build the plugin tables.
	Build(payload string) error

	// Execute a plugin command. Some commands are executed by
	// politeiad first then fowarded to the cache. If this is the case
	// the replyPayload will be populated with the politeiad reply,
	// otherwise the replyPayload will be empty.
	Exec(cmdID, cmdPayload, replyPayload string) (string, error)

	// Run a plugin hook. The given gorm.DB should be a transaction so
	// that the hook actions can be executed atomically.
	Hook(tx *gorm.DB, hookID, payload string) error
}

// Cache describes the interface used for interacting with an external
// politeiad cache.  The politeiad backend implementation serves as the source
// of truth for politeiad data and an external cache can be used if more
// performant queries are required.
type Cache interface {
	// Create a new record
	NewRecord(Record) error

	// Get the latest version of a record
	Record(string) (*Record, error)

	// Get the latest version of a record based on its prefix.
	// The length of the prefix is defined by TokenPrefixLength in the
	// politeiad api.
	RecordByPrefix(string) (*Record, error)

	// Get a specific version of a record
	RecordVersion(string, string) (*Record, error)

	// Update a record
	UpdateRecord(Record) error

	// Update the status of a record
	UpdateRecordStatus(string, string, RecordStatusT, int64,
		[]MetadataStream) error

	// Update the metadata streams of a record
	UpdateRecordMetadata(string, []MetadataStream) error

	// Get the latest version of a set of records
	Records([]string, bool) (map[string]Record, error)

	// Get the latest version of all records
	Inventory() ([]Record, error)

	// Setup the record cache tables
	Setup() error

	// Build the records cache from scratch
	Build([]Record) error

	// Register a plugin with the cache
	RegisterPlugin(Plugin) error

	// Setup the database tables for a plugin
	PluginSetup(string) error

	// Build the cache for a plugin
	PluginBuild(string, string) error

	// Execute a plugin command
	PluginExec(PluginCommand) (*PluginCommandReply, error)

	// Perform cleanup of the cache
	Close()
}
