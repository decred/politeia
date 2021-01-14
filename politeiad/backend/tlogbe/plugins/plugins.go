// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"github.com/decred/politeia/politeiad/backend"
)

const (
	// PluginSettingDataDir is the PluginSetting key for the plugin
	// data directory.
	PluginSettingDataDir = "datadir"
)

// TODO verify TlogClient implementation does not allow short tokens on writes.

// TlogClient provides an API for the plugins to interact with the tlog backend
// instances. Plugins are allowed to save, delete, and get plugin data to/from
// the tlog backend. Editing plugin data is not allowed.
type TlogClient interface {
	// BlobsSave saves the provided blobs to the tlog backend. Note,
	// hashes contains the hashes of the data encoded in the blobs. The
	// hashes must share the same ordering as the blobs.
	BlobsSave(treeID int64, keyPrefix string, blobs, hashes [][]byte,
		encrypt bool) ([][]byte, error)

	// BlobsDel deletes the blobs that correspond to the provided
	// merkle leaf hashes.
	BlobsDel(treeID int64, merkles [][]byte) error

	// MerklesByKeyPrefix returns the merkle leaf hashes for all blobs
	// that match the key prefix.
	MerklesByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error)

	// BlobsByMerkle returns the blobs with the provided merkle leaf
	// hashes. If a blob does not exist it will not be included in the
	// returned map.
	BlobsByMerkle(treeID int64, merkles [][]byte) (map[string][]byte, error)

	// BlobsByKeyPrefix returns all blobs that match the key prefix.
	BlobsByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error)

	// Timestamp returns the timestamp for the data blob that
	// corresponds to the provided merkle leaf hash.
	Timestamp(treeID int64, merkle []byte) (*backend.Timestamp, error)
}

// HookT represents the types of plugin hooks.
type HookT int

const (
	HookInvalid             HookT = 0
	HookNewRecordPre        HookT = 1
	HookNewRecordPost       HookT = 2
	HookEditRecordPre       HookT = 3
	HookEditRecordPost      HookT = 4
	HookEditMetadataPre     HookT = 5
	HookEditMetadataPost    HookT = 6
	HookSetRecordStatusPre  HookT = 7
	HookSetRecordStatusPost HookT = 8
	HookPluginPre           HookT = 9
	HookPluginPost          HookT = 10
)

var (
	// Hooks contains human readable descriptions of the plugin hooks.
	Hooks = map[HookT]string{
		HookNewRecordPre:        "new record pre",
		HookNewRecordPost:       "new record post",
		HookEditRecordPre:       "edit record pre",
		HookEditRecordPost:      "edit record post",
		HookEditMetadataPre:     "edit metadata pre",
		HookEditMetadataPost:    "edit metadata post",
		HookSetRecordStatusPre:  "set record status pre",
		HookSetRecordStatusPost: "set record status post",
		HookPluginPre:           "plugin pre",
		HookPluginPost:          "plugin post",
	}
)

// HookNewRecord is the payload for the new record hooks.
type HookNewRecord struct {
	Metadata []backend.MetadataStream `json:"metadata"`
	Files    []backend.File           `json:"files"`

	// RecordMetadata will only be present on the post new record hook.
	// This is because the record metadata requires the creation of a
	// trillian tree and the pre new record hook should execute before
	// any politeiad state is changed in case of validation errors.
	RecordMetadata *backend.RecordMetadata `json:"recordmetadata"`
}

// HookEditRecord is the payload for the edit record hooks.
type HookEditRecord struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
	FilesAdd       []backend.File           `json:"filesadd"`
	FilesDel       []string                 `json:"filesdel"`
}

// HookEditMetadata is the payload for the edit metadata hooks.
type HookEditMetadata struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	MDAppend    []backend.MetadataStream `json:"mdappend"`
	MDOverwrite []backend.MetadataStream `json:"mdoverwrite"`
}

// HookSetRecordStatus is the payload for the set record status hooks.
type HookSetRecordStatus struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

// PluginClient provides an API for the tlog backend to use when interacting
// with plugins. All tlogbe plugins must implement the pluginClient interface.
type PluginClient interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Cmd executes the provided plugin command.
	Cmd(treeID int64, token []byte, cmd, payload string) (string, error)

	// Hook executes the provided plugin hook.
	Hook(h HookT, payload string) error

	// Fsck performs a plugin file system check.
	Fsck() error
}
