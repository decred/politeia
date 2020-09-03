// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backend"
)

type HookT int

const (
	// Plugin hooks
	HookInvalid             HookT = 0
	HookNewRecordPre        HookT = 1
	HookNewRecordPost       HookT = 2
	HookEditRecordPre       HookT = 3
	HookEditRecordPost      HookT = 4
	HookEditMetadataPre     HookT = 5
	HookEditMetadataPost    HookT = 6
	HookSetRecordStatusPre  HookT = 7
	HookSetRecordStatusPost HookT = 8
)

var (
	// Hooks contains human readable plugin hook descriptions.
	Hooks = map[HookT]string{
		HookNewRecordPre:        "new record pre",
		HookNewRecordPost:       "new record post",
		HookEditRecordPre:       "edit record pre",
		HookEditRecordPost:      "edit record post",
		HookEditMetadataPre:     "edit metadata pre",
		HookEditMetadataPost:    "edit metadata post",
		HookSetRecordStatusPre:  "set record status pre",
		HookSetRecordStatusPost: "set record status post",
	}
)

// NewRecord is the payload for the HookNewRecordPre and HookNewRecordPost
// hooks.
type NewRecord struct {
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// EncodeNewRecord encodes a NewRecord into a JSON byte slice.
func EncodeNewRecord(nr NewRecord) ([]byte, error) {
	return json.Marshal(nr)
}

// DecodeNewRecord decodes a JSON byte slice into a NewRecord.
func DecodeNewRecord(payload []byte) (*NewRecord, error) {
	var nr NewRecord
	err := json.Unmarshal(payload, &nr)
	if err != nil {
		return nil, err
	}
	return &nr, nil
}

// EditRecord is the payload for the EditRecordPre and EditRecordPost hooks.
type EditRecord struct {
	// Current record
	Record backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
	FilesAdd       []backend.File           `json:"filesadd"`
	FilesDel       []string                 `json:"filesdel"`
}

// EncodeEditRecord encodes an EditRecord into a JSON byte slice.
func EncodeEditRecord(nr EditRecord) ([]byte, error) {
	return json.Marshal(nr)
}

// DecodeEditRecord decodes a JSON byte slice into a EditRecord.
func DecodeEditRecord(payload []byte) (*EditRecord, error) {
	var nr EditRecord
	err := json.Unmarshal(payload, &nr)
	if err != nil {
		return nil, err
	}
	return &nr, nil
}

// SetRecordStatus is the payload for the HookSetRecordStatusPre and
// HookSetRecordStatusPost hooks.
type SetRecordStatus struct {
	// Current record
	Record backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

// EncodeSetRecordStatus encodes a SetRecordStatus into a JSON byte slice.
func EncodeSetRecordStatus(srs SetRecordStatus) ([]byte, error) {
	return json.Marshal(srs)
}

// DecodeSetRecordStatus decodes a JSON byte slice into a SetRecordStatus.
func DecodeSetRecordStatus(payload []byte) (*SetRecordStatus, error) {
	var srs SetRecordStatus
	err := json.Unmarshal(payload, &srs)
	if err != nil {
		return nil, err
	}
	return &srs, nil
}

/// Plugin provides an API for the tlogbe to use when interacting with plugins.
// All tlogbe plugins must implement the Plugin interface.
type Plugin interface {
	// Perform plugin setup
	Setup() error

	// Execute a plugin command
	Cmd(cmd, payload string) (string, error)

	// Execute a plugin hook
	Hook(h HookT, payload string) error

	// Perform a plugin file system check
	Fsck() error
}
