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
	// hooks contains human readable plugin hook descriptions.
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

// newRecord is the payload for the hookNewRecordPre and hookNewRecordPost
// hooks.
type newRecord struct {
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// encodeNewRecord encodes a newRecord into a JSON byte slice.
func encodeNewRecord(nr newRecord) ([]byte, error) {
	return json.Marshal(nr)
}

// decodeNewRecord decodes a JSON byte slice into a newRecord.
func decodeNewRecord(payload []byte) (*newRecord, error) {
	var nr newRecord
	err := json.Unmarshal(payload, &nr)
	if err != nil {
		return nil, err
	}
	return &nr, nil
}

// editRecord is the payload for the hookEditRecordPre and hookEditRecordPost
// hooks.
type editRecord struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
	FilesAdd       []backend.File           `json:"filesadd"`
	FilesDel       []string                 `json:"filesdel"`
}

// encodeEditRecord encodes an editRecord into a JSON byte slice.
func encodeEditRecord(er editRecord) ([]byte, error) {
	return json.Marshal(er)
}

// decodeEditRecord decodes a JSON byte slice into a editRecord.
func decodeEditRecord(payload []byte) (*editRecord, error) {
	var er editRecord
	err := json.Unmarshal(payload, &er)
	if err != nil {
		return nil, err
	}
	return &er, nil
}

// setRecordStatus is the payload for the hookSetRecordStatusPre and
// hookSetRecordStatusPost hooks.
type setRecordStatus struct {
	// Current record
	Current backend.Record `json:"record"`

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

// encodeSetRecordStatus encodes a setRecordStatus into a JSON byte slice.
func encodeSetRecordStatus(srs setRecordStatus) ([]byte, error) {
	return json.Marshal(srs)
}

// decodeSetRecordStatus decodes a JSON byte slice into a setRecordStatus.
func decodeSetRecordStatus(payload []byte) (*setRecordStatus, error) {
	var srs setRecordStatus
	err := json.Unmarshal(payload, &srs)
	if err != nil {
		return nil, err
	}
	return &srs, nil
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
