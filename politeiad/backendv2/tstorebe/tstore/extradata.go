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
	// Unvetted blobs are saved as encrypted blobs and their keys will
	// be prefixed with the encryption key prefix. Use the key() method
	// when retrieving the kv store key from the extra data so that
	// this prefix is attached.
	Key string `json:"k"`

	// Desc contains the blob entry data descriptor.
	Desc string `json:"d"`

	// State indicates the record state of the blob that this leaf
	// corresponds to. Unvetted blobs are encrypted prior to being
	// saved to the kv store.
	//
	// State will only be populated for blobs that contain record
	// data. For example, the extra data for an anchor leaf will
	// not contain a state since an anchor leaf is not record
	// content.
	State backend.StateT `json:"s,omitempty"`
}

// newExtraData returns a new extraData.
//
// The encryption key prefix, if one exists, is stripped from the key before
// creating the extra data. This is done because the same blob can exist in the
// kv store as both an encrypted blob and a cleartext blob since unvetted blobs
// are originally saved as encrypted, then are re-saved as cleartext once a
// record is made public. Even though there are two different blobs in the kv
// store, there is only one tlog leaf for both blobs. Adding a prefix for
// encrypted blobs allows the single tlog leaf to point to both blobs. The
// encryption key prefix is added at runtime by the key() method based on the
// extra data State field.
func newExtraData(key, desc string, state backend.StateT) *extraData {
	// A UUID string is 36 bytes. Only use the last
	// 36 bytes of the key so that all prefixes are
	// stripped.
	return &extraData{
		Key:   key[len(key)-36:],
		Desc:  desc,
		State: state,
	}
}

// key returns the kv store key for the blob.
//
// Unvetted blobs are saved as encrypted blobs and require the encryption key
// prefix to be attached.
func (e *extraData) key() string {
	if e.State == backend.StateUnvetted {
		return encryptionKeyPrefix + e.Key
	}
	return e.Key
}

// keyCleartext returns the kv store key for the cleartext version of the blob.
func (e *extraData) keyCleartext() string {
	return e.Key
}

// encode returns the JSON encoded extra data.
func (e *extraData) encode() ([]byte, error) {
	// Sanity check. The key should only ever be a
	// 36 byte UUID string.
	if len(e.Key) != 36 {
		return nil, errors.Errorf("invalid key %v", e.Key)
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
