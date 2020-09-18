// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backend"
)

type hookT int

const (
	// Plugin hooks
	hookInvalid             hookT = 0
	hookNewRecordPre        hookT = 1
	hookNewRecordPost       hookT = 2
	hookEditRecordPre       hookT = 3
	hookEditRecordPost      hookT = 4
	hookEditMetadataPre     hookT = 5
	hookEditMetadataPost    hookT = 6
	hookSetRecordStatusPre  hookT = 7
	hookSetRecordStatusPost hookT = 8
)

var (
	// hooks contains human readable descriptions of the plugin hooks.
	hooks = map[hookT]string{
		hookNewRecordPre:        "new record pre",
		hookNewRecordPost:       "new record post",
		hookEditRecordPre:       "edit record pre",
		hookEditRecordPost:      "edit record post",
		hookEditMetadataPre:     "edit metadata pre",
		hookEditMetadataPost:    "edit metadata post",
		hookSetRecordStatusPre:  "set record status pre",
		hookSetRecordStatusPost: "set record status post",
	}
)

// hookNewRecord is the payload for the new record hooks.
type hookNewRecord struct {
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

func encodeHookNewRecord(hnr hookNewRecord) ([]byte, error) {
	return json.Marshal(hnr)
}

func decodeHookNewRecord(payload []byte) (*hookNewRecord, error) {
	var hnr hookNewRecord
	err := json.Unmarshal(payload, &hnr)
	if err != nil {
		return nil, err
	}
	return &hnr, nil
}

// hookEditRecord is the payload for the edit record hooks.
type hookEditRecord struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
	FilesAdd       []backend.File           `json:"filesadd"`
	FilesDel       []string                 `json:"filesdel"`
}

func encodeHookEditRecord(her hookEditRecord) ([]byte, error) {
	return json.Marshal(her)
}

func decodeHookEditRecord(payload []byte) (*hookEditRecord, error) {
	var her hookEditRecord
	err := json.Unmarshal(payload, &her)
	if err != nil {
		return nil, err
	}
	return &her, nil
}

// hookSetRecordStatus is the payload for the set record status hooks.
type hookSetRecordStatus struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

func encodeHookSetRecordStatus(hsrs hookSetRecordStatus) ([]byte, error) {
	return json.Marshal(hsrs)
}

func decodeHookSetRecordStatus(payload []byte) (*hookSetRecordStatus, error) {
	var hsrs hookSetRecordStatus
	err := json.Unmarshal(payload, &hsrs)
	if err != nil {
		return nil, err
	}
	return &hsrs, nil
}

// pluginClient provides an API for the tlog backend to use when interacting
// with plugins. All tlogbe plugins must implement the pluginClient interface.
type pluginClient interface {
	// setup performs any required plugin setup.
	setup() error

	// cmd executes the provided plugin command.
	cmd(cmd, payload string) (string, error)

	// hook executes the provided plugin hook.
	hook(h hookT, payload string) error

	// fsck performs a plugin file system check.
	fsck() error
}
