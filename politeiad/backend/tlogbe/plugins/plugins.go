// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import "github.com/decred/politeia/politeiad/backend"

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

// Client provides an API for a tlog instance to use when interacting with a
// plugin. All tlog plugins must implement the Client interface.
type Client interface {
	// Setup performs any required plugin setup.
	Setup() error

	// Cmd executes a plugin command.
	Cmd(treeID int64, token []byte, cmd, payload string) (string, error)

	// Hook executes a plugin hook.
	Hook(h HookT, payload string) error

	// Fsck performs a plugin file system check.
	Fsck() error
}
