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

// NewRecordPre is the payload for the HookNewRecordPre hook.
type NewRecordPre struct {
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// EncodeNewRecordPre encodes a NewRecordPre into a JSON byte slice.
func EncodeNewRecordPre(nrp NewRecordPre) ([]byte, error) {
	return json.Marshal(nrp)
}

// DecodeNewRecordPre decodes a JSON byte slice into a NewRecordPre.
func DecodeNewRecordPre(payload []byte) (*NewRecordPre, error) {
	var nrp NewRecordPre
	err := json.Unmarshal(payload, &nrp)
	if err != nil {
		return nil, err
	}
	return &nrp, nil
}

// NewRecordPost is the payload for the HookNewRecordPost hook.
type NewRecordPost struct {
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	Metadata       []backend.MetadataStream `json:"metadata"`
	Files          []backend.File           `json:"files"`
}

// EncodeNewRecordPost encodes a NewRecordPost into a JSON byte slice.
func EncodeNewRecordPost(nrp NewRecordPost) ([]byte, error) {
	return json.Marshal(nrp)
}

// DecodeNewRecordPost decodes a JSON byte slice into a NewRecordPost.
func DecodeNewRecordPost(payload []byte) (*NewRecordPost, error) {
	var nrp NewRecordPost
	err := json.Unmarshal(payload, &nrp)
	if err != nil {
		return nil, err
	}
	return &nrp, nil
}

// SetRecordStatusPre is the payload for the HookSetRecordStatusPre hook.
type SetRecordStatusPre struct {
	Record backend.Record `json:"record"` // Current record

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

// EncodeSetRecordStatusPre encodes a SetRecordStatusPre into a JSON byte
// slice.
func EncodeSetRecordStatusPre(srsp SetRecordStatusPre) ([]byte, error) {
	return json.Marshal(srsp)
}

// DecodeSetRecordStatusPre decodes a JSON byte slice into a
// SetRecordStatusPre.
func DecodeSetRecordStatusPre(payload []byte) (*SetRecordStatusPre, error) {
	var srsp SetRecordStatusPre
	err := json.Unmarshal(payload, &srsp)
	if err != nil {
		return nil, err
	}
	return &srsp, nil
}

// SetRecordStatusPost is the payload for the HookSetRecordStatusPost hook.
type SetRecordStatusPost struct {
	Record backend.Record `json:"record"` // Current record

	// Updated fields
	RecordMetadata backend.RecordMetadata   `json:"recordmetadata"`
	MDAppend       []backend.MetadataStream `json:"mdappend"`
	MDOverwrite    []backend.MetadataStream `json:"mdoverwrite"`
}

// EncodeSetRecordStatusPost encodes a SetRecordStatusPost into a JSON byte
// slice.
func EncodeSetRecordStatusPost(srsp SetRecordStatusPost) ([]byte, error) {
	return json.Marshal(srsp)
}

// DecodeSetRecordStatusPost decodes a JSON byte slice into a
// SetRecordStatusPost.
func DecodeSetRecordStatusPost(payload []byte) (*SetRecordStatusPost, error) {
	var srsp SetRecordStatusPost
	err := json.Unmarshal(payload, &srsp)
	if err != nil {
		return nil, err
	}
	return &srsp, nil
}

// Plugin provides an API for the tlogbe to use when interacting with plugins.
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
