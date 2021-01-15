// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import "github.com/decred/politeia/politeiad/backend"

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

// HookPluginPre is the payload for the plugin pre hook.
type HookPluginPre struct {
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"`
}

// HookPluginPost is the payload for the plugin post hook.
type HookPluginPost struct {
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"`
	Reply    string `json:"reply"`
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
