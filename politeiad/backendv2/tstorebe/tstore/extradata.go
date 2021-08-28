// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/json"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/google/uuid"
)

const (
	// encryptionKeyPrefix is prefixed onto key-value store keys if the
	// data is encrypted. We do this so that when a record is made
	// public we can save the plain text record content blobs using the
	// same keys, but without the prefix. Using a new key for the plain
	// text blobs would not work since we cannot append a new leaf onto
	// the tlog tree without getting a duplicate leaf error.
	encryptionKeyPrefix = "e_"
)

// extraData is the structure that is stored in the tlog leaf's ExtraData
// field. It contains the kv store key for the leaf's blob entry as well as
// other cached metadata for the blob entry.
//
// The JSON keys in this structure have been abbreviated to minimize the amount
// of data that we store in each tlog leaf.
type extraData struct {
	// Key contains the key-value store key for the corresponding blob.
	// If the blob is part of an unvetted record, the key will need to
	// be prefixed with the encryptionKeyPrefix in order to retrieve the
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

// key returns the kv store key for the blob.
//
// Unvetted blobs are encrypted prior to being saved to the kv store and the
// key is prefixed with the encryption key prefix. See the extra data struct
// documentation for an explination of why this is done.
func (e *extraData) key() string {
	if e.State == backend.StateUnvetted {
		return encryptionKeyPrefix + e.Key
	}
	return e.Key
}

// keyNoPrefix returns the kv store key without any encryption prefix,
// regardless of whether the leaf corresponds to a unvetted blob.
func (e *extraData) keyNoPrefix() string {
	return e.Key
}

// encode returns the JSON encoded extra data.
//
// The encryption key prefix, if one exists, is stripped from the key before
// encoding the extra data. This is done because the same blob can exist in the
// kv store as both an encrypted blob and a cleartext blob since unvetted blobs
// are originally saved as encrypted, then are re-saved as cleartext once a
// record is made public. Even though there are two different blobs in the kv
// store, there is only one tlog leaf for both blobs. Adding a prefix for
// encrypted blobs allows the single tlog leaf to point to both blobs. The
// encryption key prefix is added at runtime based on the extra data State
// field.
func (e *extraData) encode() ([]byte, error) {
	// A UUID string is 36 bytes. Only use the last
	// 36 bytes of the key so that all prefixes are
	// stripped.
	ed := extraData{
		Key:   e.Key[len(e.Key)-36:],
		Desc:  e.Desc,
		State: e.State,
	}
	b, err := json.Marshal(ed)
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

// newStoreKey returns a new key for the key-value store.
//
// If the data is encrypted the key is prefixed with the encryption key prefix.
// This is done because the same blob can exist in the kv store as both an
// encrypted blob and a cleartext blob since unvetted blobs are originally
// saved as encrypted, then are re-saved as cleartext once a record is made
// public. Even though there are two different blobs in the kv store, there is
// only one tlog leaf for both blobs. Adding a prefix for encrypted blobs
// allows the single tlog leaf to point to both blobs.
func newStoreKey(encrypt bool) string {
	k := uuid.New().String()
	if encrypt {
		k = encryptionKeyPrefix + k
	}
	return k
}
