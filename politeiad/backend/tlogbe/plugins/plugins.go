// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// HookT represents the types of plugin hooks.
type HookT int

const (
	HookTypeInvalid             HookT = 0
	HookTypeNewRecordPre        HookT = 1
	HookTypeNewRecordPost       HookT = 2
	HookTypeEditRecordPre       HookT = 3
	HookTypeEditRecordPost      HookT = 4
	HookTypeEditMetadataPre     HookT = 5
	HookTypeEditMetadataPost    HookT = 6
	HookTypeSetRecordStatusPre  HookT = 7
	HookTypeSetRecordStatusPost HookT = 8
	HookTypePluginPre           HookT = 9
	HookTypePluginPost          HookT = 10
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

// RecordStateT represents a record state. The record state is included in all
// hook payloads so that a plugin has the ability to implement different
// behaviors for different states.
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
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
	FilesAdd       []backend.File           `json:"filesadd"`
	FilesDel       []string                 `json:"filesdel"`
}

// HookEditMetadata is the payload for the pre and post edit metadata hooks.
type HookEditMetadata struct {
	State   RecordStateT   `json:"state"`
	Current backend.Record `json:"record"` // Current record

	// Updated fields
	MDAppend    []backend.MetadataStream `json:"mdappend"`
	MDOverwrite []backend.MetadataStream `json:"mdoverwrite"`
}

// HookSetRecordStatus is the payload for the pre and post set record status
// hooks.
type HookSetRecordStatus struct {
	State   RecordStateT   `json:"state"`
	Current backend.Record `json:"record"` // Current record

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
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

// Client provides an API for a tlog instance to use when interacting with a
// plugin. All tlog plugins must implement the Client interface.
type Client interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Cmd executes a plugin command.
	Cmd(treeID int64, token []byte, cmd, payload string) (string, error)

	// Hook executes a plugin hook.
	Hook(treeID int64, token []byte, h HookT, payload string) error

	// Fsck performs a plugin file system check.
	Fsck() error
}

// TODO plugins should only have access to the backend methods for the tlog
// instance that they're registered on.
// TODO the plugin hook state should not really be required. This issue is that
// some vetted plugins require unvetted hooks, ex. verifying the linkto in
// vote metadata. Possile solution, keep the layer violations in the
// application plugin (pi) instead of the functionality plugin (ticketvote).

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
}
