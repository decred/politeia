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
	// keyPrefixEncrypted is prefixed onto key-value store keys if the
	// data is encrypted. We do this so that when a record is made
	// public we can save the plain text record content blobs using the
	// same keys, but without the prefix. Using a new key for the plain
	// text blobs would not work since we cannot append a new leaf onto
	// the tlog without getting a duplicate leaf error.
	keyPrefixEncrypted = "e_"
)

// extraData is the data that is stored in the log leaf ExtraData field. It is
// saved as a JSON encoded byte slice. The JSON keys have been abbreviated to
// minimize the size of a trillian log leaf.
type extraData struct {
	// Key contains the key-value store key. If this blob is part of an
	// unvetted record the key will need to be prefixed with the
	// keyPrefixEncrypted in order to retrieve the blob from the kv
	// store. Use the extraData.storeKey() method to retrieve the key.
	// Do NOT reference this key directly.
	Key string `json:"k"`

	// Desc contains the blob entry data descriptor.
	Desc string `json:"d"`

	// State indicates the record state of the blob that this leaf
	// corresponds to. Unvetted blobs encrypted prior to being saved
	// to the store. When retrieving unvetted blobs from the kv store
	// the keyPrefixEncrypted prefix must be added to the Key field.
	// State will not be populated for anchor records.
	State backend.StateT `json:"s,omitempty"`
}

// storeKey returns the kv store key for the blob. If the blob is part of an
// unvetted record it will be saved as an encrypted blob in the kv store and
// the key is prefixed with keyPrefixEncrypted.
func (e *extraData) storeKey() string {
	if e.State == backend.StateUnvetted {
		return keyPrefixEncrypted + e.Key
	}
	return e.Key
}

// storeKeyNoPrefix returns the kv store key without any encryption prefix,
// even if the leaf corresponds to a unvetted blob.
func (e *extraData) storeKeyNoPrefix() string {
	return e.Key
}

// extraDataEncode encodes prepares an extraData using the provided arguments
// then returns the JSON encoded byte slice.
func extraDataEncode(key, desc string, state backend.StateT) ([]byte, error) {
	// The encryption prefix is stripped from the key if one exists.
	ed := extraData{
		Key:   storeKeyCleaned(key),
		Desc:  desc,
		State: state,
	}
	b, err := json.Marshal(ed)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// extraDataDecode decodes a JSON byte slice into a extraData.
func extraDataDecode(b []byte) (*extraData, error) {
	var ed extraData
	err := json.Unmarshal(b, &ed)
	if err != nil {
		return nil, err
	}
	return &ed, nil
}

// storeKeyNew returns a new key for the key-value store. If the data is
// encrypted the key is prefixed.
func storeKeyNew(encrypt bool) string {
	k := uuid.New().String()
	if encrypt {
		k = keyPrefixEncrypted + k
	}
	return k
}

// storeKeyCleaned strips the key-value store key of the encryption prefix if
// one is present.
func storeKeyCleaned(key string) string {
	// A uuid string is 36 bytes. Return the last 36 bytes of the
	// string. This will strip the prefix if it exists.
	return key[len(key)-36:]
}
