// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// HookT represents a plugin hook.
type HookT int

const (
	// HookTypeInvalid is an invalid plugin hook.
	HookTypeInvalid HookT = 0

	// HootTypeNewRecordPre is called before a new record is saved to
	// disk.
	HookTypeNewRecordPre HookT = 1

	// HootTypeNewRecordPost is called after a new record is saved to
	// disk.
	HookTypeNewRecordPost HookT = 2

	// HookTypeEditRecordPre is called before a record update is saved
	// to disk.
	HookTypeEditRecordPre HookT = 3

	// HookTypeEditRecordPost is called after a record update is saved
	// to disk.
	HookTypeEditRecordPost HookT = 4

	// HookTypeEditMetadataPre is called before a metadata update is
	// saved to disk.
	HookTypeEditMetadataPre HookT = 5

	// HookTypeEditMetadataPost is called after a metadata update is
	// saved to disk.
	HookTypeEditMetadataPost HookT = 6

	// HookTypeSetRecordStatusPre is called before a record status
	// change is saved to disk.
	HookTypeSetRecordStatusPre HookT = 7

	// HookTypeSetRecordStatusPost is called after a record status
	// change is saved to disk.
	HookTypeSetRecordStatusPost HookT = 8

	// HookTypePluginPre is called before a plugin command is executed.
	HookTypePluginPre HookT = 9

	// HookTypePluginPost is called after a plugin command is executed.
	HookTypePluginPost HookT = 10
)

var (
	// Hooks contains human readable descriptions of the plugin hooks.
	Hooks = map[HookT]string{
		HookTypeNewRecordPre:        "new record pre",
		HookTypeNewRecordPost:       "new record post",
		HookTypeEditRecordPre:       "edit record pre",
		HookTypeEditRecordPost:      "edit record post",
		HookTypeEditMetadataPre:     "edit metadata pre",
		HookTypeEditMetadataPost:    "edit metadata post",
		HookTypeSetRecordStatusPre:  "set record status pre",
		HookTypeSetRecordStatusPost: "set record status post",
		HookTypePluginPre:           "plugin pre",
		HookTypePluginPost:          "plugin post",
	}
)

// RecordStateT represents a record state.
type RecordStateT int

const (
	// RecordStateInvalid is an invalid record state.
	RecordStateInvalid RecordStateT = 0

	// RecordStateUnvetted represents an unvetted record.
	RecordStateUnvetted RecordStateT = 1

	// RecordStateVetted represents a vetted record.
	RecordStateVetted RecordStateT = 2
)

// HookNewRecordPre is the payload for the pre new record hook. The record
// state is not inlcuded since all new records will have a record state of
// unvetted.
type HookNewRecordPre struct {
	Metadata []backend.MetadataStream `json:"metadata"`
	Files    []backend.File           `json:"files"`
}

// HookNewRecordPost is the payload for the post new record hook. The record
// state is not inlcuded since all new records will have a record state of
// unvetted.  RecordMetadata is only be present on the post new record hook
// since the record metadata requires the creation of a trillian tree and the
// pre new record hook should execute before any politeiad state is changed in
// case of validation errors.
type HookNewRecordPost struct {
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
	RecordMetadata *backend.RecordMetadata  `json:"recordmetadata"`
}

// HookEditRecord is the payload for the pre and post edit record hooks.
type HookEditRecord struct {
	State   RecordStateT   `json:"state"`
	Current backend.Record `json:"record"` // Current record

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// HookEditMetadata is the payload for the pre and post edit metadata hooks.
type HookEditMetadata struct {
	State   RecordStateT   `json:"state"`
	Current backend.Record `json:"record"` // Current record

	// Updated fields
	Metadata []backend.MetadataStream `json:"metadata"`
}

// HookSetRecordStatus is the payload for the pre and post set record status
// hooks.
type HookSetRecordStatus struct {
	State   RecordStateT   `json:"state"`
	Current backend.Record `json:"record"` // Current record

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
}

// HookPluginPre is the payload for the pre plugin hook.
type HookPluginPre struct {
	State    RecordStateT `json:"state"`
	Token    string       `json:"token"`
	PluginID string       `json:"pluginid"`
	Cmd      string       `json:"cmd"`
	Payload  string       `json:"payload"`
}

// HookPluginPost is the payload for the post plugin hook. The post plugin hook
// includes the plugin reply.
type HookPluginPost struct {
	State    RecordStateT `json:"state"`
	PluginID string       `json:"pluginid"`
	Cmd      string       `json:"cmd"`
	Payload  string       `json:"payload"`
	Reply    string       `json:"reply"`
}

// PluginClient provides an API for a tlog instance to use when interacting
// with a plugin. All tlog plugins must implement the PluginClient interface.
type PluginClient interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Cmd executes a plugin command.
	Cmd(treeID int64, token []byte, cmd, payload string) (string, error)

	// Hook executes a plugin hook.
	Hook(treeID int64, token []byte, h HookT, payload string) error

	// Fsck performs a plugin file system check.
	Fsck(treeIDs []int64) error
}

// TlogClient provides an API for plugins to interact with a tlog instance.
// Plugins are allowed to save, delete, and get plugin data to/from the tlog
// backend. Editing plugin data is not allowed.
type TlogClient interface {
	// BlobSave saves a BlobEntry to the tlog instance. The BlobEntry
	// will be encrypted prior to being written to disk if the tlog
	// instance has an encryption key set. The digest of the data,
	// i.e. BlobEntry.Digest, can be thought of as the blob ID and can
	// be used to get/del the blob from tlog.
	BlobSave(treeID int64, dataType string, be store.BlobEntry) error

	// BlobsDel deletes the blobs that correspond to the provided
	// digests.
	BlobsDel(treeID int64, digests [][]byte) error

	// Blobs returns the blobs that correspond to the provided digests.
	// If a blob does not exist it will not be included in the returned
	// map.
	Blobs(treeID int64, digests [][]byte) (map[string]store.BlobEntry, error)

	// BlobsByDataType returns all blobs that match the data type. The
	// blobs will be ordered from oldest to newest.
	BlobsByDataType(treeID int64, keyPrefix string) ([]store.BlobEntry, error)

	// DigestsByDataType returns the digests of all blobs that match
	// the data type.
	DigestsByDataType(treeID int64, dataType string) ([][]byte, error)

	// Timestamp returns the timestamp for the blob that correpsonds
	// to the digest.
	Timestamp(treeID int64, digest []byte) (*backend.Timestamp, error)

	// Record returns a version of a record.
	Record(treeID int64, version uint32) (*backend.Record, error)

	// RecordLatest returns the most recent version of a record.
	RecordLatest(treeID int64) (*backend.Record, error)
}
