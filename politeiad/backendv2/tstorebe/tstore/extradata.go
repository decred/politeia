// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/json"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	// keyPrefixEncrypted is prefixed onto key-value store keys if the
	// data is encrypted. We do this so that when a record is made
	// public we can save the plain text record content blobs using the
	// same keys, but without the prefix. Using a new key for the plain
	// text blobs would not work since we cannot append a new leaf onto
	// the tlog tree without getting a duplicate leaf error.
	keyPrefixEncrypted = "e_"
)

// extraData is the structure that is stored in the trillain log leaf's
// ExtraData field.  It contains the kv store key for the leaf's blob entry
// as well as other cached metadata for the blob entry.
//
// The JSON keys for this structure have been abbreviated to minimize the size
// of the log leaf.
type extraData struct {
	// Key contains the key-value store key for the corresponding blob.
	// If the blob is part of an unvetted record, the key will need to
	// be prefixed with the keyPrefixEncrypted in order to retrieve the
	// blob from the kv store. This is handled by the extraData key()
	// method. Do NOT reference the key field directly.
	Key string `json:"k"`

	// Desc contains the blob entry data descriptor.
	Desc string `json:"d"`

	// State indicates the record state of the blob that this leaf
	// corresponds to. Unvetted blobs are encrypted prior to being
	// saved to the kv store.
	//
	// State will only be populated for blobs that contain record
	// data. Example: the extra data for an anchor leaf will not
	// contain a state.
	State backend.StateT `json:"s,omitempty"`
}

// newExtraData returns a new extraData.
func newExtraData(key, desc string, state backend.StateT) *extraData {
	return &extraData{
		Key:   key,
		Desc:  desc,
		State: state,
	}
}

// key returns the kv store key for the blob. If the blob is part of an
// unvetted record it will be saved as an encrypted blob in the kv store and
// the key will be prefixed with the keyPrefixEncrypted.
func (e *extraData) key() string {
	if e.State == backend.StateUnvetted {
		return keyPrefixEncrypted + e.Key
	}
	return e.Key
}

// keyNoPrefix returns the kv store key without any encryption prefix,
// regardless of whether the leaf corresponds to a unvetted blob.
func (e *extraData) keyNoPrefix() string {
	return e.Key
}

// encode returns the JSON encoded extra data.
func (e *extraData) encode() ([]byte, error) {
	// Sanity check. Verify that the encryption key prefix is
	// not present. The encryption key prefix should only be
	// added at runtime. The key should be a 36 byte UUID.
	if len(e.Key) != 36 {
		return nil, errors.Errorf("invalid key length: %v %v",
			e.Desc, e.Key)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// decodeExtraData decodes a JSON byte slice into a extraData.
func decodeExtraData(b []byte) (*extraData, error) {
	var ed extraData
	err := json.Unmarshal(b, &ed)
	if err != nil {
		return nil, err
	}
	return &ed, nil
}

// newStoreKey returns a new key for the key-value store. If the data is
// encrypted the key is prefixed.
func newStoreKey(encrypt bool) string {
	k := uuid.New().String()
	if encrypt {
		k = keyPrefixEncrypted + k
	}
	return k
}
